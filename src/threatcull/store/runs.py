# SPDX-License-Identifier: AGPL-3.0-only
"""Runs: the recorded history of every Fetch and Compile."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
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
) -> None:
    conn.execute(
        "UPDATE runs SET finished_at = ?, status = ?, counts = ?, error = ? WHERE id = ?",
        (ts(now), status, json.dumps(dict(counts or {})), error, run_id),
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
    )


def recent_runs(conn: sqlite3.Connection, limit: int = 20) -> list[Run]:
    rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC, id DESC LIMIT ?", (limit,))
    return [_to_run(row) for row in rows]


def last_run(conn: sqlite3.Connection, run_type: RunType) -> Run | None:
    """The most recent Run of ``run_type``, however many other-typed Runs came after it.

    Unlike filtering :func:`recent_runs` in Python, this never misses an old
    Compile behind a long run of Fetches (e.g. the scheduler's own Fetch
    cadence): the ``WHERE type = ?`` runs in SQL, not over a capped window.
    """
    row = conn.execute(
        "SELECT * FROM runs WHERE type = ? ORDER BY started_at DESC, id DESC LIMIT 1",
        (run_type,),
    ).fetchone()
    return _to_run(row) if row is not None else None


def fail_unfinished_runs(
    conn: sqlite3.Connection,
    run_type: RunType,
    *,
    source_id: str | None,
    now: datetime,
    error: str,
) -> int:
    """Mark still-``running`` Runs of this type (and Source) failed; returns how many.

    For a crash after ``start_run`` but before ``finish_run``: the Run that
    was started is closed as failed instead of staying "running" for ever.
    """
    return conn.execute(
        "UPDATE runs SET finished_at = ?, status = 'failed', error = ? "
        "WHERE type = ? AND source_id IS ? AND status = 'running'",
        (ts(now), error, run_type, source_id),
    ).rowcount
