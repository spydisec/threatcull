# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta

from threatcull.clock import ts
from threatcull.store.runs import finish_run, recent_runs, start_run


def test_run_lifecycle(conn: sqlite3.Connection, now: datetime) -> None:
    run_id = start_run(conn, "compile", now=now)
    later = now + timedelta(seconds=5)
    finish_run(conn, run_id, "blocked", now=later, counts={"ip-high": 10}, error="shrink")
    (run,) = recent_runs(conn)
    assert (run.type, run.status, run.counts, run.error) == (
        "compile",
        "blocked",
        {"ip-high": 10},
        "shrink",
    )
    assert (run.started_at, run.finished_at) == (ts(now), ts(later))


def test_recent_runs_are_newest_first_and_limited(conn: sqlite3.Connection, now: datetime) -> None:
    for i in range(3):
        start_run(conn, "fetch", now=now + timedelta(minutes=i), source_id=f"s{i}")
    runs = recent_runs(conn, limit=2)
    assert [r.source_id for r in runs] == ["s2", "s1"]
    assert all(r.status == "running" for r in runs)
