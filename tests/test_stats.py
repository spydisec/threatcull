# SPDX-License-Identifier: AGPL-3.0-only
"""Compile Stats: what a Compile cleaned up, recorded on its Run for the dashboard."""

import sqlite3
from datetime import datetime
from pathlib import Path

from tests.test_compiling import _setup
from threatcull.compiling import compile_outputs
from threatcull.indicators import Indicator
from threatcull.policy.stats import CompileStats, SourceShare
from threatcull.store.allowlist import add_entry
from threatcull.store.db import SCHEMA_VERSION
from threatcull.store.runs import finish_run, last_run, start_run
from threatcull.store.sightings import record_fetch_success


def _fetch_run(conn: sqlite3.Connection, source_id: str, invalid: int, now: datetime) -> None:
    run_id = start_run(conn, "fetch", now=now, source_id=source_id)
    finish_run(conn, run_id, "ok", now=now, counts={"parsed": 99, "invalid": invalid})


def test_compile_records_the_cleanup_funnel(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    # Source A lists 45.9.20.1-10, Source B lists 45.9.20.1 (see _setup).
    _setup(conn, now)
    _fetch_run(conn, "a", 5, now)
    _fetch_run(conn, "a", 3, now)  # the newest Fetch of a Source counts
    _fetch_run(conn, "b", 1, now)
    add_entry(conn, "45.9.20.8/29", "partner", now=now)  # 45.9.20.8-10 (.8 is in the /29)
    add_entry(conn, "45.9.20.7", "office", mine=True, now=now)

    report = compile_outputs(conn, tmp_path, now=now)

    stats = report.stats
    assert stats is not None
    assert stats.listed == 11
    assert stats.unique == 10
    assert stats.duplicates == 1
    assert stats.rejected == 4
    assert stats.allowlisted == 3
    assert stats.home == 1
    assert stats.tiers == {"high": 0, "medium": 1, "low": 5}
    assert stats.published == 6
    assert stats.sources == {"a": SourceShare(entries=10, unique=9), "b": SourceShare(1, 0)}
    assert stats.kinds == {
        "ip": {"high": 0, "medium": 1, "low": 5},
        "domain": {"high": 0, "medium": 0, "low": 0},
    }
    assert stats.categories == {"ip": {"malicious": 6}, "domain": {}}
    assert stats.kept("ip") == 6


def test_stats_are_stored_on_the_compile_run(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    report = compile_outputs(conn, tmp_path, now=now)
    run = last_run(conn, "compile")
    assert run is not None
    assert CompileStats.from_json(run.stats) == report.stats


def test_runs_without_stats_read_back_as_none() -> None:
    assert CompileStats.from_json({}) is None


def test_schema_adds_the_stats_column_to_runs(conn: sqlite3.Connection) -> None:
    assert SCHEMA_VERSION >= 5
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    assert "stats" in columns


def test_stats_from_before_the_kind_split_still_read_back() -> None:
    old = {
        "listed": 3,
        "unique": 2,
        "rejected": 0,
        "allowlisted": 0,
        "home": 0,
        "tiers": {"high": 0, "medium": 1, "low": 1},
        "sources": {"a": [2, 1]},
    }
    stats = CompileStats.from_json(old)
    assert stats is not None
    assert stats.kinds == {}
    assert stats.kept("domain") == 0


def test_blocklisted_ranges_are_counted_and_left_out_of_every_output(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    record_fetch_success(
        conn,
        "b",
        {Indicator("45.9.20.1", "ip"), Indicator("45.9.21.0/24", "cidr")},
        now=now,
        etag=None,
        last_modified=None,
    )
    stats = compile_outputs(conn, tmp_path, now=now).stats
    assert stats is not None
    assert stats.ranges == 1
    assert stats.published == 10
    assert CompileStats.from_json(stats.to_json()) == stats
    older = {key: value for key, value in stats.to_json().items() if key != "ranges"}
    restored = CompileStats.from_json(older)  # a Run recorded before this field
    assert restored is not None
    assert restored.ranges == 0
    published = (tmp_path / "ips.txt").read_text()
    assert "45.9.20.1\n" in published
    assert "45.9.21.0/24" not in published
