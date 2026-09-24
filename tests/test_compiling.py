# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.factories import make_entry
from threatcull.compiling import compile_outputs, shrink_reasons
from threatcull.indicators import Indicator
from threatcull.outputs.render import tail
from threatcull.store.allowlist import add_entry
from threatcull.store.outputs import OutputFormat, OutputSpec, create_output, get_output
from threatcull.store.runs import recent_runs
from threatcull.store.settings import Settings
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog

IPS = {Indicator(f"45.9.20.{i}", "ip") for i in range(1, 11)}


def _setup(conn: sqlite3.Connection, now: datetime) -> None:
    sync_catalog(
        conn,
        [
            make_entry(
                id="a",
                url="https://a.example/1",
                default_enabled=True,
                name="Source A",
                licence="CC0",
                licence_url="https://a.example/l",
            ),
            make_entry(id="b", url="https://b.example/1", default_enabled=True, name="Source B"),
        ],
    )
    create_output(conn, OutputSpec("ips", "ip", frozenset({"malicious"}), "low", None, "plain"))
    create_output(
        conn, OutputSpec("ips-two", "ip", frozenset({"malicious"}), "medium", None, "csv")
    )
    record_fetch_success(conn, "a", IPS, now=now, etag=None, last_modified=None)
    record_fetch_success(
        conn, "b", {Indicator("45.9.20.1", "ip")}, now=now, etag=None, last_modified=None
    )


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text().splitlines() if not line.startswith("#")]


def test_compile_publishes_every_output(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    report = compile_outputs(conn, tmp_path, now=now)
    assert report.status == "ok"
    assert report.counts == {"ips": 10, "ips-two": 1}
    assert len(_lines(tmp_path / "ips.txt")) == 10
    assert "Source A | CC0 | https://a.example/l" in (tmp_path / "ips.txt").read_text()
    assert (
        (tmp_path / "ips-two.csv").read_text().splitlines()[1].startswith("45.9.20.1,ip,2,medium")
    )
    assert get_output(conn, "ips").last_count == 10
    assert recent_runs(conn)[0].status == "ok"


def test_allowlisted_indicators_are_excluded(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    add_entry(conn, "45.9.20.0/29", "partner range", now=now)
    report = compile_outputs(conn, tmp_path, now=now)
    assert report.allowlisted == 7
    assert report.counts["ips"] == 3


def test_shrink_guard_blocks_and_keeps_previous_files(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    compile_outputs(conn, tmp_path, now=now)
    before = (tmp_path / "ips.txt").read_text()
    later = now + timedelta(hours=1)
    record_fetch_success(
        conn, "a", {Indicator("45.9.20.1", "ip")}, now=later, etag=None, last_modified=None
    )
    report = compile_outputs(conn, tmp_path, now=later)
    assert report.status == "blocked"
    assert any("ips would shrink from 10 to 1" in reason for reason in report.reasons)
    assert (tmp_path / "ips.txt").read_text() == before
    assert get_output(conn, "ips").last_count == 10
    assert recent_runs(conn)[0].status == "blocked"


def test_force_overrides_the_guard(conn: sqlite3.Connection, now: datetime, tmp_path: Path) -> None:
    _setup(conn, now)
    compile_outputs(conn, tmp_path, now=now)
    later = now + timedelta(hours=1)
    record_fetch_success(
        conn, "a", {Indicator("45.9.20.1", "ip")}, now=later, etag=None, last_modified=None
    )
    assert compile_outputs(conn, tmp_path, now=later, force=True).status == "ok"
    assert len(_lines(tmp_path / "ips.txt")) == 1


def test_stale_sources_block_compile(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    report = compile_outputs(conn, tmp_path, now=now + timedelta(hours=80))
    assert report.status == "blocked"
    assert report.stale_sources == ("a", "b")


def test_first_publish_is_never_blocked(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    create_output(conn, OutputSpec("empty", "domain", frozenset({"spam"}), "low", None, "hosts"))
    report = compile_outputs(conn, tmp_path, now=now)
    assert (report.status, report.counts) == ("ok", {"empty": 0})
    assert (tmp_path / "empty.txt").exists()


def test_shrink_reasons_rules() -> None:
    settings = Settings()
    assert shrink_reasons({"x": 100}, {"x": 60}, stale=0, enabled=4, settings=settings) == []
    assert shrink_reasons({"x": None}, {"x": 0}, stale=0, enabled=4, settings=settings) == []
    assert len(shrink_reasons({"x": 100}, {"x": 40}, stale=2, enabled=4, settings=settings)) == 2


def test_blocked_compile_leaves_no_temp_files(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    report = compile_outputs(conn, tmp_path / "out", now=now + timedelta(hours=80))
    assert report.status == "blocked"
    assert list((tmp_path / "out").iterdir()) == []


def test_failure_mid_compile_publishes_nothing_and_cleans_up(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(conn, now)
    out_dir = tmp_path / "out"
    calls: list[str] = []

    def flaky(fmt: OutputFormat, count: int) -> str:
        calls.append(fmt)
        if len(calls) == 2:
            raise OSError("disk full")
        return tail(fmt, count)

    # The first Output is fully staged, the second fails while being written.
    monkeypatch.setattr("threatcull.outputs.stream.tail", flaky)
    with pytest.raises(OSError, match="disk full"):
        compile_outputs(conn, out_dir, now=now)
    assert list(out_dir.iterdir()) == []
    assert recent_runs(conn)[0].status == "failed"
    assert get_output(conn, "ips").last_count is None
