# SPDX-License-Identifier: AGPL-3.0-only
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.factories import make_entry
from threatcull import compiling
from threatcull.clock import ts
from threatcull.compiling import (
    compile_outputs,
    frozen_source_ids,
    is_frozen,
    optimize_database,
    shrink_reasons,
    stale_source_ids,
)
from threatcull.indicators import Indicator
from threatcull.outputs.render import tail
from threatcull.store.allowlist import add_entry
from threatcull.store.outputs import (
    OutputFormat,
    OutputSpec,
    create_output,
    get_output,
    record_published,
)
from threatcull.store.runs import recent_runs
from threatcull.store.settings import Settings
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import get_source, list_sources, set_enabled, sync_catalog

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
    assert "Source A | https://a.example/1" in (tmp_path / "ips.txt").read_text()
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


def test_parent_of_an_allowlisted_domain_is_in_no_output(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    sync_catalog(
        conn,
        [
            make_entry(
                id="d",
                url="https://d.example/1",
                kind="domain",
                default_enabled=True,
            )
        ],
    )
    domains = {Indicator(v, "domain") for v in ("example.com", "other.example.com")}
    record_fetch_success(conn, "d", domains, now=now, etag=None, last_modified=None)
    formats: tuple[OutputFormat, ...] = ("plain", "hosts", "adguard", "rpz", "csv", "json")
    for fmt in formats:
        create_output(
            conn, OutputSpec(f"dom-{fmt}", "domain", frozenset({"malicious"}), "low", None, fmt)
        )
    add_entry(conn, "login.example.com", "staff sign-in", now=now)
    report = compile_outputs(conn, tmp_path, now=now)
    assert report.allowlisted == 1
    for fmt in formats:
        assert report.counts[f"dom-{fmt}"] == 1
        text = next(tmp_path.glob(f"dom-{fmt}.*")).read_text()
        assert "other.example.com" in text
        assert text.replace("other.example.com", "").count("example.com") == 0


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


def test_disabling_a_source_resets_the_shrink_baseline(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    # "ips" publishes 10 (Source A) + overlap from B; disabling A shrinks it to 1.
    _setup(conn, now)
    assert compile_outputs(conn, tmp_path, now=now).status == "ok"
    set_enabled(conn, "a", False)

    report = compile_outputs(conn, tmp_path, now=now + timedelta(minutes=1))

    assert report.status == "ok"
    assert report.counts["ips"] == 1
    assert report.rebaselined == ("ips", "ips-two")  # both are fed by Source A
    assert get_output(conn, "ips").last_count == 1


def test_an_upstream_collapse_with_the_same_sources_is_still_blocked(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    assert compile_outputs(conn, tmp_path, now=now).status == "ok"
    later = now + timedelta(minutes=1)
    record_fetch_success(
        conn, "a", {Indicator("45.9.20.1", "ip")}, now=later, etag=None, last_modified=None
    )

    report = compile_outputs(conn, tmp_path, now=later)

    assert report.status == "blocked"
    assert report.rebaselined == ()
    assert get_output(conn, "ips").last_count == 10


def test_published_outputs_remember_the_sources_that_fed_them(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    compile_outputs(conn, tmp_path, now=now)
    assert get_output(conn, "ips").last_sources == frozenset({"a", "b"})


def test_compile_refreshes_planner_statistics(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(conn, now)
    calls: list[sqlite3.Connection] = []
    monkeypatch.setattr(compiling, "optimize_database", calls.append)
    compile_outputs(conn, tmp_path, now=now)
    assert calls == [conn]


def test_optimize_runs_on_a_real_database(conn: sqlite3.Connection, now: datetime) -> None:
    _setup(conn, now)
    optimize_database(conn)
    assert conn.execute("PRAGMA analysis_limit").fetchone()[0] == compiling.ANALYSIS_LIMIT


def test_optimize_failure_never_fails_the_compile(tmp_path: Path) -> None:
    closed = sqlite3.connect(tmp_path / "closed.db")
    closed.close()
    optimize_database(closed)  # logged, not raised


def _with_new_sources(conn: sqlite3.Connection, count: int) -> None:
    """Sources a and b (fetched by ``_setup``) plus ``count`` enabled, never fetched."""
    entries = [
        make_entry(id=s, url=f"https://{s}.example/1", default_enabled=True, name=f"Source {s}")
        for s in ("a", "b")
    ]
    entries += [
        make_entry(id=f"new{i}", url=f"https://n{i}.example/1", default_enabled=True)
        for i in range(count)
    ]
    sync_catalog(conn, entries)


def test_a_never_fetched_source_is_not_stale(conn: sqlite3.Connection, now: datetime) -> None:
    # Enabled Sources wait up to an hour for their first Fetch (#60); meanwhile they
    # have no Sightings, so they must neither count as Stale nor block the Compile.
    _setup(conn, now)
    _with_new_sources(conn, 4)
    blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    assert stale_source_ids(blocklists, now=now, settings=Settings()) == ()


def test_new_sources_do_not_block_the_compile(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    _with_new_sources(conn, 4)  # 4 of 6 enabled blocklists have never been fetched
    assert compile_outputs(conn, tmp_path, now=now).status == "ok"


def test_a_compile_records_its_stage_timings(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    compile_outputs(conn, tmp_path, now=now)
    run = recent_runs(conn)[0]
    assert list(run.timings) == ["prune", "score", "allowlist", "stats", "outputs", "publish"]
    assert run.stats["listed"] > 0  # the cleanup numbers are still there


def _changed_ago(conn: sqlite3.Connection, now: datetime, days: int, **entry: object) -> None:
    sync_catalog(conn, [make_entry(id="old", default_enabled=True, **entry)])
    record_fetch_success(
        conn, "old", {Indicator("45.9.20.1", "ip")}, now=now, etag=None, last_modified=None
    )
    conn.execute(
        "UPDATE sources SET last_changed_at = ? WHERE id = 'old'",
        (ts(now - timedelta(days=days)),),
    )


def test_a_source_unchanged_for_the_limit_is_frozen(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _changed_ago(conn, now, 30)
    assert is_frozen(get_source(conn, "old"), now=now, settings=Settings())
    assert frozen_source_ids([get_source(conn, "old")], now=now, settings=Settings()) == ("old",)


def test_a_source_changed_within_the_limit_is_not_frozen(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _changed_ago(conn, now, 29)
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings())


def test_the_limit_comes_from_the_setting(conn: sqlite3.Connection, now: datetime) -> None:
    _changed_ago(conn, now, 30)
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings(frozen_after_days=400))


def test_allowlist_sources_are_never_frozen(conn: sqlite3.Connection, now: datetime) -> None:
    _changed_ago(conn, now, 3000, role="allowlist", category="infrastructure")
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings())


def test_disabled_sources_are_not_frozen(conn: sqlite3.Connection, now: datetime) -> None:
    _changed_ago(conn, now, 3000)
    set_enabled(conn, "old", False)
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings())


def test_a_failing_source_shows_as_failed_not_frozen(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _changed_ago(conn, now, 3000)
    conn.execute("UPDATE sources SET last_error = 'HTTP 500' WHERE id = 'old'")
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings())


def test_a_source_without_a_change_date_is_not_frozen(
    conn: sqlite3.Connection, now: datetime
) -> None:
    _changed_ago(conn, now, 3000)
    conn.execute("UPDATE sources SET last_changed_at = NULL WHERE id = 'old'")
    assert not is_frozen(get_source(conn, "old"), now=now, settings=Settings())


def test_a_frozen_source_still_counts_in_the_compile(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path
) -> None:
    _setup(conn, now)
    conn.execute("UPDATE sources SET last_changed_at = '2021-01-01T00:00:00+00:00'")
    blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    assert set(frozen_source_ids(blocklists, now=now, settings=Settings())) == {"a", "b"}
    report = compile_outputs(conn, tmp_path, now=now)
    assert report.status == "ok"
    assert report.counts == {"ips": 10, "ips-two": 1}


def test_outputs_are_fsynced_before_they_replace_the_published_files(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(conn, now)
    events: list[tuple[str, str]] = []
    real_fsync, real_replace = os.fsync, Path.replace

    def fsync(fd: int) -> None:
        events.append(("fsync", str(Path(f"/proc/self/fd/{fd}").readlink())))
        real_fsync(fd)

    def replace(self: Path, target: Path) -> Path:
        events.append(("replace", str(self)))
        return real_replace(self, target)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(Path, "replace", replace)
    assert compile_outputs(conn, tmp_path, now=now).status == "ok"
    replaced = [path for kind, path in events if kind == "replace"]
    assert len(replaced) == 2
    for tmp in replaced:
        assert events.index(("fsync", tmp)) < events.index(("replace", tmp))
    # The directory is synced after the last rename, so the renames survive a power cut too.
    last_replace = max(i for i, (kind, _) in enumerate(events) if kind == "replace")
    assert ("fsync", str(tmp_path)) in events[last_replace:]


def test_published_counts_are_recorded_all_or_nothing(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(conn, now)
    before = {name: get_output(conn, name).last_count for name in ("ips", "ips-two")}
    real = record_published
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise sqlite3.OperationalError("disk I/O error")
        real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("threatcull.compiling.record_published", flaky)
    with pytest.raises(sqlite3.OperationalError):
        compile_outputs(conn, tmp_path, now=now)
    assert {name: get_output(conn, name).last_count for name in ("ips", "ips-two")} == before


def test_newly_created_output_folders_are_synced_in_their_parents_before_the_counts(
    conn: sqlite3.Connection, now: datetime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(conn, now)
    out_dir = tmp_path / "data" / "outputs"  # neither folder exists yet
    events: list[tuple[str, str]] = []
    real_fsync, real_record = os.fsync, record_published

    def fsync(fd: int) -> None:
        events.append(("fsync", str(Path(f"/proc/self/fd/{fd}").readlink())))
        real_fsync(fd)

    def record(*args: object, **kwargs: object) -> None:
        events.append(("record", ""))
        real_record(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr("threatcull.compiling.record_published", record)
    assert compile_outputs(conn, out_dir, now=now).status == "ok"
    first_record = events.index(("record", ""))
    synced_before = {path for kind, path in events[:first_record] if kind == "fsync"}
    assert {str(out_dir), str(out_dir.parent), str(tmp_path)} <= synced_before
