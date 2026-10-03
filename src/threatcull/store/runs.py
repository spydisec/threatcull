# SPDX-License-Identifier: AGPL-3.0-only
"""Runs: the recorded history of every Fetch and Compile."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from threatcull.clock import ts

RunType = Literal["fetch", "compile"]
RunStatus = Literal["running", "ok", "not_modified", "failed", "blocked"]


@dataclass(frozen=True, slots=True)
class Run:
    id: int
    type: RunType
    source_id: str | None
    started_at: str
    finished_at: str | None
    status: RunStatus
    counts: dict[str, int]
    error: str | None
    # A Compile's hits on the operator's own network: (value, comma-joined Source ids), capped.
    home_hits: tuple[tuple[str, str], ...] = ()
    # A Compile's cleanup numbers (``policy.stats.CompileStats.to_json``) and, for every
    # Run since 2.4, ``timings``: seconds per stage (``timing.StageTimer``).
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> int | None:
        """How long the Run took; ``None`` while it runs."""
        if self.finished_at is None:
            return None
        took = datetime.fromisoformat(self.finished_at) - datetime.fromisoformat(self.started_at)
        return max(0, int(took.total_seconds()))

    @property
    def timings(self) -> dict[str, float]:
        """Seconds per stage, in the order the stages ran; {} for older Runs."""
        timings: dict[str, float] = self.stats.get("timings", {})
        return timings


# Fetch and Compile pass one logical ``now`` to both start_run and finish_run, so
# the Sightings and Outputs of a run share a timestamp. The real elapsed time is
# measured here with a monotonic clock and added at finish_run, so a run's
# finished_at shows how long it actually took. Keyed by connection and run id;
# a run is always started and finished on the same connection.
_started: dict[tuple[int, int], tuple[datetime, float]] = {}
_started_lock = threading.Lock()
_MAX_TRACKED = 1000  # runs that never finish (a crash mid-run) must not pile up
_monotonic = time.monotonic  # replaced in tests


def start_run(
    conn: sqlite3.Connection, run_type: RunType, *, now: datetime, source_id: str | None = None
) -> int:
    cursor = conn.execute(
        "INSERT INTO runs (type, source_id, started_at, status) VALUES (?, ?, ?, 'running')",
        (run_type, source_id, ts(now)),
    )
    run_id = int(cursor.lastrowid or 0)
    with _started_lock:
        if len(_started) >= _MAX_TRACKED:
            _started.clear()
        _started[(id(conn), run_id)] = (now, _monotonic())
    return run_id


def _finished_at(conn: sqlite3.Connection, run_id: int, now: datetime) -> datetime:
    """``now``, or the start plus the real elapsed time when that is later."""
    with _started_lock:
        started = _started.pop((id(conn), run_id), None)
    if started is None:
        return now
    logical_start, mark = started
    return max(now, logical_start + timedelta(seconds=_monotonic() - mark))


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    status: RunStatus,
    *,
    now: datetime,
    counts: Mapping[str, int] | None = None,
    error: str | None = None,
    home_hits: Sequence[tuple[str, str]] = (),
    stats: Mapping[str, Any] | None = None,
) -> None:
    conn.execute(
        "UPDATE runs SET finished_at = ?, status = ?, counts = ?, error = ?, home_hits = ?, "
        "stats = ? WHERE id = ?",
        (
            ts(_finished_at(conn, run_id, now)),
            status,
            json.dumps(dict(counts or {})),
            error,
            json.dumps([list(hit) for hit in home_hits]),
            json.dumps(dict(stats or {})),
            run_id,
        ),
    )


def _to_run(row: sqlite3.Row) -> Run:
    return Run(
        id=row["id"],
        type=row["type"],
        source_id=row["source_id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        counts=json.loads(row["counts"]),
        error=row["error"],
        home_hits=tuple((value, sources) for value, sources in json.loads(row["home_hits"])),
        stats=json.loads(row["stats"]),
    )


def recent_runs(conn: sqlite3.Connection, limit: int = 20) -> list[Run]:
    rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC, id DESC LIMIT ?", (limit,))
    return [_to_run(row) for row in rows]


def last_run(
    conn: sqlite3.Connection, run_type: RunType, *, statuses: Sequence[RunStatus] | None = None
) -> Run | None:
    """The most recent Run of ``run_type``, however many other-typed Runs came after it.

    Unlike filtering :func:`recent_runs` in Python, this never misses an old
    Compile behind a long run of Fetches (e.g. the scheduler's own Fetch
    cadence): the ``WHERE type = ?`` runs in SQL, not over a capped window.

    ``statuses``, when given, restricts the match to Runs that finished with one of
    those statuses (e.g. the dashboard's own-network alert must skip a failed
    Compile and fall back to the last one that actually finished).
    """
    if statuses is None:
        row = conn.execute(
            "SELECT * FROM runs WHERE type = ? ORDER BY started_at DESC, id DESC LIMIT 1",
            (run_type,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM runs WHERE type = :type "
            "AND status IN (SELECT value FROM json_each(:statuses)) "
            "ORDER BY started_at DESC, id DESC LIMIT 1",
            {"type": run_type, "statuses": json.dumps(list(statuses))},
        ).fetchone()
    return _to_run(row) if row is not None else None


INTERRUPTED_ERROR = "interrupted by restart"


def latest_run_id(conn: sqlite3.Connection) -> int:
    """The highest Run id so far (``0`` if none): a mark for :func:`fail_unfinished_runs`."""
    row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM runs").fetchone()
    return int(row[0])


def fail_unfinished_runs(
    conn: sqlite3.Connection,
    run_type: RunType,
    *,
    source_id: str | None,
    started_after: int,
    now: datetime,
    error: str,
) -> int:
    """Mark ``running`` Runs of this type (and Source) with id > ``started_after`` failed.

    For a crash after ``start_run`` but before ``finish_run``: the caller takes
    a mark with :func:`latest_run_id` first, so only the Run its own call
    started is closed, never an older row some other process left behind
    (those are :func:`fail_interrupted_runs`'s job). Returns how many.
    """
    return conn.execute(
        "UPDATE runs SET finished_at = ?, status = 'failed', error = ? "
        "WHERE type = ? AND source_id IS ? AND status = 'running' AND id > ?",
        (ts(now), error, run_type, source_id, started_after),
    ).rowcount


def fail_interrupted_runs(conn: sqlite3.Connection, *, now: datetime) -> int:
    """At start-up: every Run still ``running`` was cut short by a restart; mark it failed."""
    return conn.execute(
        "UPDATE runs SET finished_at = ?, status = 'failed', error = ? WHERE status = 'running'",
        (ts(now), INTERRUPTED_ERROR),
    ).rowcount


def compile_history(
    conn: sqlite3.Connection, *, since: str | None = None, limit: int = 2000
) -> list[Run]:
    """Finished Compiles that recorded Compile Stats, oldest first: the newest ``limit``,
    or only those started at or after ``since``."""
    rows = conn.execute(
        "SELECT * FROM runs WHERE type = 'compile' AND status IN ('ok', 'blocked') "
        "AND stats != '{}' AND started_at >= ? ORDER BY started_at DESC, id DESC LIMIT ?",
        (since or "", limit),
    )
    return [_to_run(row) for row in rows][::-1]


def recent_fetches(conn: sqlite3.Connection, limit: int = 500) -> list[Run]:
    """The newest ``limit`` Fetch Runs, newest first."""
    rows = conn.execute(
        "SELECT * FROM runs WHERE type = 'fetch' ORDER BY started_at DESC, id DESC LIMIT ?",
        (limit,),
    )
    return [_to_run(row) for row in rows]


def running_run(conn: sqlite3.Connection, *, after_id: int = 0) -> Run | None:
    """The newest Run still marked ``running`` with an id above ``after_id``, if any."""
    row = conn.execute(
        "SELECT * FROM runs WHERE status = 'running' AND id > ? ORDER BY id DESC LIMIT 1",
        (after_id,),
    ).fetchone()
    return _to_run(row) if row is not None else None


def previous_duration(
    conn: sqlite3.Connection, run_type: RunType, *, source_id: str | None, before_id: int
) -> int | None:
    """Seconds the last finished Run of the same kind took, or ``None`` if unknown.

    Runs recorded before finish times were real (finished_at == started_at)
    don't count: their 0 s would be a wrong guide.
    """
    row = conn.execute(
        "SELECT started_at, finished_at FROM runs "
        "WHERE type = ? AND source_id IS ? AND id < ? AND status != 'running' "
        "AND finished_at IS NOT NULL AND finished_at > started_at "
        "ORDER BY id DESC LIMIT 1",
        (run_type, source_id, before_id),
    ).fetchone()
    if row is None:
        return None
    took = datetime.fromisoformat(row["finished_at"]) - datetime.fromisoformat(row["started_at"])
    return int(took.total_seconds())


def runs_after(conn: sqlite3.Connection, run_type: RunType, after_id: int) -> int:
    """How many Runs of ``run_type`` have an id above ``after_id``."""
    count: int = conn.execute(
        "SELECT COUNT(*) FROM runs WHERE type = ? AND id > ?", (run_type, after_id)
    ).fetchone()[0]
    return count
