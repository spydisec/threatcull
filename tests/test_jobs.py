# SPDX-License-Identifier: AGPL-3.0-only
"""PipelineRunner: Fetch + Compile on its own connection, one run at a time."""

import threading
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from tests.factories import make_entry
from threatcull.fetcher import Fetcher, FetchResult
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.runs import recent_runs
from threatcull.store.sources import sync_catalog
from threatcull.web import jobs
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner

WAIT = 10.0  # seconds; every wait in these tests is bounded


class BlockingFetcher:
    """A fake fetcher that signals ``entered`` and then waits for ``release``."""

    def __init__(self, text: str = "45.9.20.1\n") -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.text = text

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.entered.set()
        self.release.wait(WAIT)
        return FetchResult("ok", self.text)

    def factory(self) -> Callable[[], Fetcher]:
        return lambda: self


class ExplodingFetcher:
    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise RuntimeError("boom")


def _seed(data_dir: Path) -> None:
    conn = open_db(data_dir)
    try:
        sync_catalog(
            conn,
            [make_entry(id="a", url="https://a.example/1", default_enabled=True, name="Source A")],
        )
        ensure_default_outputs(conn)
    finally:
        conn.close()


def test_run_fetches_and_compiles(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    fake.release.set()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    result = runner.run()
    assert result.status == "ok"
    assert result.fetched == 1
    assert result.failed_sources == ()
    assert "ip-high" in result.counts
    assert runner.last_result == result
    assert not runner.is_running()
    conn = open_db(tmp_path)
    try:
        assert {run.type for run in recent_runs(conn, 10)} == {"fetch", "compile"}
    finally:
        conn.close()


def test_second_run_is_refused_while_one_is_in_progress(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    try:
        assert runner.start_background() is True
        assert fake.entered.wait(WAIT)
        assert runner.is_running()
        assert runner.start_background() is False
        assert runner.run().status == "already_running"
        assert runner.compile_only(force=True).status == "already_running"
    finally:
        fake.release.set()
        assert runner.wait(WAIT)
    assert not runner.is_running()
    assert runner.last_result is not None
    assert runner.last_result.status == "ok"
    # The lock is free again: a new run goes through.
    assert runner.run().status == "ok"


def _explode(*args: object, **kwargs: object) -> NoReturn:
    raise RuntimeError("database gone")


def test_a_crashing_run_releases_the_lock_and_records_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    # A fetcher error is only a failed Fetch; a crash in Compile fails the run.
    monkeypatch.setattr(jobs, "compile_outputs", _explode)
    result = runner.run()
    assert result.status == "failed"
    assert result.error is not None
    assert "database gone" in result.error
    assert result.failed_sources == ("a",)
    assert not runner.is_running()


def test_background_crash_is_caught(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    monkeypatch.setattr(jobs, "compile_outputs", _explode)
    assert runner.start_background() is True
    assert runner.wait(WAIT)
    assert not runner.is_running()
    assert runner.last_result is not None
    assert runner.last_result.status == "failed"


def test_compile_only_does_not_fetch(tmp_path: Path) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    result = runner.compile_only(force=True)
    assert result.status == "ok"
    assert result.fetched == 0
    conn = open_db(tmp_path)
    try:
        assert [run.type for run in recent_runs(conn, 10)] == ["compile"]
    finally:
        conn.close()


def test_wait_waits_for_a_synchronous_run_in_another_thread(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    worker = threading.Thread(target=runner.run, daemon=True)  # not start_background
    worker.start()
    try:
        assert fake.entered.wait(WAIT)
        assert runner.wait(0.05) is False  # no background thread, but not idle
    finally:
        fake.release.set()
    assert runner.wait(WAIT) is True
    worker.join(WAIT)
    assert not runner.is_running()


def test_wait_ignores_a_stale_finished_background_thread(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    fake.release.set()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    assert runner.start_background() is True
    assert runner.wait(WAIT) is True
    # The old thread object is finished; a synchronous run now holds the lock.
    fake.release.clear()
    fake.entered.clear()
    worker = threading.Thread(target=runner.run, daemon=True)
    worker.start()
    try:
        assert fake.entered.wait(WAIT)
        assert runner.wait(0.05) is False
    finally:
        fake.release.set()
    assert runner.wait(WAIT) is True
    worker.join(WAIT)


def test_wait_returns_once_idle_after_a_blocked_compile_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    entered = threading.Event()
    release = threading.Event()

    def slow_compile(*args: object, **kwargs: object) -> NoReturn:
        entered.set()
        release.wait(WAIT)
        raise RuntimeError("slow and then broken")

    monkeypatch.setattr(jobs, "compile_outputs", slow_compile)
    try:
        worker = threading.Thread(target=runner.compile_only, daemon=True)
        worker.start()
        assert entered.wait(WAIT)
        assert runner.wait(0.05) is False
        release.set()
        assert runner.wait(WAIT) is True
        worker.join(WAIT)
    finally:
        release.set()


class _BrokenThread:
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("can't start new thread")


def test_start_background_releases_the_lock_if_the_thread_cannot_be_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    monkeypatch.setattr(jobs, "Thread", _BrokenThread)
    with pytest.raises(RuntimeError, match="can't start"):
        runner.start_background()
    assert not runner.is_running()
    assert runner.wait(0.05) is True


def test_run_source_fetches_one_enabled_source(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    fake.release.set()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    result = runner.run_source("a")
    assert result.status == "ok"
    assert result.fetched == 1
    assert runner.last_result is None  # the dashboard's "last run" is for whole runs
    assert not runner.is_running()
    conn = open_db(tmp_path)
    try:
        assert [(r.type, r.source_id, r.status) for r in recent_runs(conn, 10)] == [
            ("fetch", "a", "ok")
        ]
    finally:
        conn.close()


def test_run_source_skips_unknown_and_disabled_sources(tmp_path: Path) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=ExplodingFetcher)
    assert runner.run_source("nope").status == "skipped"
    conn = open_db(tmp_path)
    try:
        conn.execute("UPDATE sources SET enabled = 0 WHERE id = 'a'")
        assert runner.run_source("a").status == "skipped"
        assert recent_runs(conn, 10) == []
    finally:
        conn.close()


def test_run_source_is_refused_while_busy(tmp_path: Path) -> None:
    _seed(tmp_path)
    fake = BlockingFetcher()
    runner = PipelineRunner(tmp_path, fetcher_factory=fake.factory())
    try:
        assert runner.start_background() is True
        assert fake.entered.wait(WAIT)
        assert runner.run_source("a").status == "already_running"
    finally:
        fake.release.set()
        assert runner.wait(WAIT)


def _broken_factory() -> Fetcher:
    raise RuntimeError("no fetcher today")


def test_run_source_records_a_failed_run_when_it_crashes(tmp_path: Path) -> None:
    _seed(tmp_path)
    runner = PipelineRunner(tmp_path, fetcher_factory=_broken_factory)
    result = runner.run_source("a")
    assert result.status == "failed"
    assert result.failed_sources == ("a",)
    assert result.error is not None
    assert "no fetcher today" in result.error
    assert not runner.is_running()
    conn = open_db(tmp_path)
    try:
        runs = recent_runs(conn, 10)
        assert [(r.type, r.source_id, r.status) for r in runs] == [("fetch", "a", "failed")]
        assert runs[0].error is not None
        assert "no fetcher today" in runs[0].error
    finally:
        conn.close()
