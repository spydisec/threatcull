# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta

from threatcull.clock import ts
from threatcull.store.runs import finish_run, last_run, recent_runs, start_run


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


def test_last_run_returns_none_when_that_type_never_ran(conn: sqlite3.Connection) -> None:
    assert last_run(conn, "compile") is None


def test_last_run_finds_a_compile_behind_many_later_fetches(
    conn: sqlite3.Connection, now: datetime
) -> None:
    # Reproduces the scheduler's own cadence: many Fetch Runs interleaved
    # after a Compile must never push it out of last_run's view, unlike a
    # capped scan over recent_runs() would.
    compile_id = start_run(conn, "compile", now=now)
    finish_run(conn, compile_id, "ok", now=now, counts={"ip-high": 5})
    for i in range(150):
        later = now + timedelta(minutes=i + 1)
        fetch_id = start_run(conn, "fetch", now=later, source_id=f"s{i}")
        finish_run(conn, fetch_id, "ok", now=later)
    run = last_run(conn, "compile")
    assert run is not None
    assert (run.id, run.type, run.status) == (compile_id, "compile", "ok")


def test_last_run_ignores_other_types(conn: sqlite3.Connection, now: datetime) -> None:
    start_run(conn, "fetch", now=now, source_id="s")
    assert last_run(conn, "compile") is None
