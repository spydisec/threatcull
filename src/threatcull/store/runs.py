# SPDX-License-Identifier: AGPL-3.0-only
"""Runs: the recorded history of every Fetch and Compile."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

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
    # A Compile's Home Network hits: (value, comma-joined Source ids), capped.
    home_hits: tuple[tuple[str, str], ...] = ()


def start_run(
    conn: sqlite3.Connection, run_type: RunType, *, now: datetime, source_id: str | None = None
) -> int:
    cursor = conn.execute(
        "INSERT INTO runs (type, source_id, started_at, status) VALUES (?, ?, ?, 'running')",
        (run_type, source_id, ts(now)),
    )
    return int(cursor.lastrowid or 0)


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    status: RunStatus,
    *,
    now: datetime,
    counts: Mapping[str, int] | None = None,
    error: str | None = None,
    home_hits: Sequence[tuple[str, str]] = (),
) -> None:
    conn.execute(
        "UPDATE runs SET finished_at = ?, status = ?, counts = ?, error = ?, home_hits = ? "
        "WHERE id = ?",
        (
            ts(now),
            status,
            json.dumps(dict(counts or {})),
            error,
            json.dumps([list(hit) for hit in home_hits]),
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
    those statuses (e.g. the dashboard's Home Network banner must skip a failed
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
