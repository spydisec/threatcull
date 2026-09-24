# SPDX-License-Identifier: AGPL-3.0-only
"""The built-in scheduler: one Fetch job per enabled Source, hourly + debounced Compile.

Nothing here sleeps for real minutes: most tests build the scheduler without
starting it and call the job functions directly; the one started scheduler
fires a job "now" and every wait on it is bounded.
"""

import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest
from apscheduler.job import Job
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from tests.factories import make_entry
from threatcull.clock import ts, utcnow
from threatcull.fetcher import Fetcher, FetchResult
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.runs import finish_run, recent_runs, start_run
from threatcull.store.sources import set_enabled, sync_catalog
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner
from threatcull.web.scheduler import (
    COMPILE_JOB_ID,
    DEBOUNCED_COMPILE_JOB_ID,
    Scheduler,
    fetch_job_id,
    fetch_retry_job_id,
)

WAIT = 10.0  # seconds; every wait in these tests is bounded


def _ok_fetcher(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
    return FetchResult("ok", "45.9.20.1\n")


def _ok_factory() -> Fetcher:
    return _ok_fetcher


def _exploding_factory() -> Fetcher:
    raise RuntimeError("fetcher factory exploded")


def _seed(data_dir: Path) -> None:
    conn = open_db(data_dir)
    try:
        sync_catalog(
            conn,
            [
                make_entry(id="a", url="https://a.example/1", default_enabled=True, name="A"),
                make_entry(
                    id="b",
                    url="https://b.example/1",
                    default_enabled=True,
                    name="B",
                    refresh_minutes=240,
                ),
                make_entry(id="c", url="https://c.example/1", default_enabled=False, name="C"),
            ],
        )
        ensure_default_outputs(conn)
    finally:
        conn.close()


def _scheduler(data_dir: Path, factory: object = _ok_factory) -> Scheduler:
    runner = PipelineRunner(data_dir, fetcher_factory=factory)  # type: ignore[arg-type]
    return Scheduler(data_dir, runner)


def _fetch_jobs(scheduler: Scheduler) -> dict[str, IntervalTrigger]:
    jobs = {}
    for job in scheduler.scheduler.get_jobs():
        if job.id.startswith("fetch:"):
            assert isinstance(job.trigger, IntervalTrigger)
            jobs[job.id] = job.trigger
    return jobs


def _set_enabled(data_dir: Path, source_id: str, enabled: bool) -> None:
    conn = open_db(data_dir)
    try:
        set_enabled(conn, source_id, enabled)
    finally:
        conn.close()


def _runs(data_dir: Path) -> list[tuple[str, str | None, str]]:
    conn = open_db(data_dir)
    try:
        return [(run.type, run.source_id, run.status) for run in recent_runs(conn, 50)]
    finally:
        conn.close()


def test_one_job_per_enabled_source_with_its_interval_and_jitter(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    jobs = _fetch_jobs(scheduler)
    assert set(jobs) == {fetch_job_id("a"), fetch_job_id("b")}
    assert jobs[fetch_job_id("a")].interval == timedelta(minutes=60)
    assert jobs[fetch_job_id("b")].interval == timedelta(minutes=240)
    # Up to 10% jitter, in seconds.
    assert jobs[fetch_job_id("a")].jitter == 60 * 60 // 10
    assert jobs[fetch_job_id("b")].jitter == 240 * 60 // 10
    compile_job = scheduler.scheduler.get_job(COMPILE_JOB_ID)
    assert compile_job is not None
    assert isinstance(compile_job.trigger, IntervalTrigger)
    assert compile_job.trigger.interval == timedelta(minutes=60)


def test_rescan_is_idempotent_and_follows_enable_disable(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    scheduler.rescan()
    assert len(_fetch_jobs(scheduler)) == 2

    _set_enabled(tmp_path, "a", False)
    _set_enabled(tmp_path, "c", True)
    scheduler.rescan()
    assert set(_fetch_jobs(scheduler)) == {fetch_job_id("b"), fetch_job_id("c")}
    assert len(scheduler.scheduler.get_jobs()) == 3  # plus the hourly Compile


def test_rescan_picks_up_a_changed_refresh_interval(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    conn = open_db(tmp_path)
    try:
        conn.execute("UPDATE sources SET refresh_minutes = 30 WHERE id = 'a'")
    finally:
        conn.close()
    scheduler.rescan()
    jobs = _fetch_jobs(scheduler)
    assert jobs[fetch_job_id("a")].interval == timedelta(minutes=30)
    assert len(jobs) == 2


def test_a_job_for_a_source_disabled_since_does_nothing(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    _set_enabled(tmp_path, "a", False)  # no rescan yet: the job still exists
    scheduler.fetch_job("a")
    assert _runs(tmp_path) == []
    assert scheduler.scheduler.get_job(DEBOUNCED_COMPILE_JOB_ID) is None


def test_successful_fetches_schedule_one_coalesced_debounced_compile(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    before = utcnow()
    scheduler.fetch_job("a")
    scheduler.fetch_job("b")
    after = utcnow()
    debounced = [
        job for job in scheduler.scheduler.get_jobs() if job.id == DEBOUNCED_COMPILE_JOB_ID
    ]
    assert len(debounced) == 1
    trigger = debounced[0].trigger
    assert isinstance(trigger, DateTrigger)
    # The later Fetch pushed it back: 2 minutes after the second completion.
    assert before + timedelta(minutes=2) <= trigger.run_date <= after + timedelta(minutes=2)
    assert [(t, s, st) for t, s, st in _runs(tmp_path)] == [
        ("fetch", "b", "ok"),
        ("fetch", "a", "ok"),
    ]
    # Running the debounced job compiles.
    scheduler.compile_job()
    assert _runs(tmp_path)[0][0] == "compile"


def test_a_failed_fetch_schedules_no_compile_and_records_a_failed_run(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path, _exploding_factory)
    scheduler.rescan()
    jobs_before = {job.id for job in scheduler.scheduler.get_jobs()}
    scheduler.fetch_job("a")  # must not raise
    assert _runs(tmp_path) == [("fetch", "a", "failed")]
    assert scheduler.scheduler.get_job(DEBOUNCED_COMPILE_JOB_ID) is None
    assert {job.id for job in scheduler.scheduler.get_jobs()} == jobs_before


class BlockingFetcher:
    """Holds the runner's lock (via start_background) until ``release`` is set."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.entered.set()
        self.release.wait(WAIT)
        return FetchResult("ok", "45.9.20.1\n")


def _busy_scheduler(data_dir: Path) -> tuple[Scheduler, BlockingFetcher]:
    fake = BlockingFetcher()
    scheduler = _scheduler(data_dir, lambda: fake)
    assert scheduler.runner.start_background() is True  # a "Run now" is in progress
    assert fake.entered.wait(WAIT)
    return scheduler, fake


def _retry_jobs(scheduler: Scheduler) -> list[Job]:
    return [job for job in scheduler.scheduler.get_jobs() if job.id.startswith("fetch-retry:")]


def test_a_busy_fetch_tick_arms_one_retry_in_about_three_minutes(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler, fake = _busy_scheduler(tmp_path)
    try:
        # Fetched just now: the regular tick is an hour out, so the retry is sooner.
        _set_last_attempt(tmp_path, "a", utcnow())
        scheduler.rescan()
        started = time.monotonic()
        before = utcnow()
        scheduler.fetch_job("a")
        scheduler.fetch_job("a")
        after = utcnow()
        assert time.monotonic() - started < 1.0  # never blocks
        retries = _retry_jobs(scheduler)
        assert [job.id for job in retries] == [fetch_retry_job_id("a")]
        run_at = retries[0].next_run_time
        assert before + timedelta(minutes=3) <= run_at
        assert run_at <= after + timedelta(minutes=3, seconds=30)
    finally:
        fake.release.set()
        assert scheduler.runner.wait(WAIT)
    runs_before = len(_runs(tmp_path))
    # The retry reuses fetch_job: now idle, it fetches and debounces a Compile.
    scheduler.fetch_job("a")
    runs = _runs(tmp_path)
    assert len(runs) == runs_before + 1
    assert runs[0] == ("fetch", "a", "ok")
    assert scheduler.scheduler.get_job(DEBOUNCED_COMPILE_JOB_ID) is not None


def test_no_retry_when_the_regular_tick_comes_sooner(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler, fake = _busy_scheduler(tmp_path)
    try:
        scheduler.rescan()
        scheduler.scheduler.modify_job(
            fetch_job_id("a"), next_run_time=utcnow() + timedelta(minutes=1)
        )
        scheduler.fetch_job("a")
        assert _retry_jobs(scheduler) == []
    finally:
        fake.release.set()
        assert scheduler.runner.wait(WAIT)


def test_a_busy_compile_rearms_the_debounced_compile(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler, fake = _busy_scheduler(tmp_path)
    try:
        before = utcnow()
        scheduler.compile_job()
        job = scheduler.scheduler.get_job(DEBOUNCED_COMPILE_JOB_ID)
        assert job is not None
        assert job.next_run_time >= before + timedelta(minutes=2)
    finally:
        fake.release.set()
        assert scheduler.runner.wait(WAIT)


def test_rescan_drops_retries_for_disabled_sources(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler, fake = _busy_scheduler(tmp_path)
    try:
        _set_last_attempt(tmp_path, "a", utcnow())
        scheduler.rescan()
        scheduler.fetch_job("a")
        assert len(_retry_jobs(scheduler)) == 1
    finally:
        fake.release.set()
        assert scheduler.runner.wait(WAIT)
    _set_enabled(tmp_path, "a", False)
    scheduler.rescan()
    assert _retry_jobs(scheduler) == []


def _set_last_attempt(data_dir: Path, source_id: str, when: datetime) -> None:
    conn = open_db(data_dir)
    try:
        conn.execute("UPDATE sources SET last_attempt_at = ? WHERE id = ?", (ts(when), source_id))
    finally:
        conn.close()


def _next_runs(scheduler: Scheduler) -> dict[str, datetime]:
    return {
        job.id: job.next_run_time
        for job in scheduler.scheduler.get_jobs()
        if job.id.startswith("fetch:")
    }


def test_never_fetched_sources_are_due_within_minutes_and_staggered(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    before = utcnow()
    scheduler.rescan()
    runs = _next_runs(scheduler)
    assert set(runs) == {fetch_job_id("a"), fetch_job_id("b")}
    for run_at in runs.values():
        assert before + timedelta(seconds=30) <= run_at <= utcnow() + timedelta(minutes=5)
    assert runs[fetch_job_id("a")] != runs[fetch_job_id("b")]
    # A second rescan leaves them where they are.
    scheduler.rescan()
    assert _next_runs(scheduler) == runs


def test_a_recently_fetched_source_waits_for_its_interval(tmp_path: Path) -> None:
    _seed(tmp_path)
    attempted = utcnow().replace(microsecond=0) - timedelta(minutes=10)
    _set_last_attempt(tmp_path, "a", attempted)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    run_at = _next_runs(scheduler)[fetch_job_id("a")]
    due = attempted + timedelta(minutes=60)
    assert due <= run_at <= due + timedelta(seconds=60 * 60 // 10)


def test_overdue_sources_are_staggered_in_due_order(tmp_path: Path) -> None:
    _seed(tmp_path)
    now = utcnow()
    _set_last_attempt(tmp_path, "a", now - timedelta(hours=3))  # due 2 h ago
    _set_last_attempt(tmp_path, "b", now - timedelta(hours=10))  # due 6 h ago: first
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    runs = _next_runs(scheduler)
    assert runs[fetch_job_id("b")] < runs[fetch_job_id("a")]
    assert runs[fetch_job_id("a")] - runs[fetch_job_id("b")] == timedelta(seconds=45)
    assert runs[fetch_job_id("b")] <= utcnow() + timedelta(seconds=31)


def _compile_next_run(scheduler: Scheduler) -> datetime:
    job = scheduler.scheduler.get_job(COMPILE_JOB_ID)
    assert job is not None
    run_at: datetime = job.next_run_time
    return run_at


def test_first_compile_comes_soon_without_a_recent_compile(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    before = utcnow()
    scheduler.start()
    try:
        run_at = _compile_next_run(scheduler)
        assert before + timedelta(minutes=5) <= run_at <= utcnow() + timedelta(minutes=5)
    finally:
        scheduler.shutdown()


def test_first_compile_follows_a_recent_compile(tmp_path: Path) -> None:
    _seed(tmp_path)
    conn = open_db(tmp_path)
    compiled = utcnow().replace(microsecond=0) - timedelta(minutes=20)
    try:
        run_id = start_run(conn, "compile", now=compiled)
        finish_run(conn, run_id, "ok", now=compiled)
    finally:
        conn.close()
    scheduler = _scheduler(tmp_path)
    scheduler.start()
    try:
        assert _compile_next_run(scheduler) == compiled + timedelta(minutes=60)
    finally:
        scheduler.shutdown()


def test_started_scheduler_survives_run_source_raising(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    called = threading.Event()

    def exploding_run_source(source_id: str) -> NoReturn:
        called.set()
        raise RuntimeError("run_source blew up")

    scheduler.runner.run_source = exploding_run_source  # type: ignore[method-assign]
    scheduler.start()
    try:
        scheduler.scheduler.modify_job(fetch_job_id("a"), next_run_time=utcnow())
        assert called.wait(WAIT)
        deadline = time.monotonic() + WAIT
        while time.monotonic() < deadline:
            job = scheduler.scheduler.get_job(fetch_job_id("a"))
            if job is not None and job.next_run_time > utcnow() + timedelta(minutes=30):
                break
            time.sleep(0.05)
        assert scheduler.scheduler.running
        job = scheduler.scheduler.get_job(fetch_job_id("a"))
        assert job is not None
        assert job.next_run_time > utcnow() + timedelta(minutes=30)
        assert {j.id for j in scheduler.scheduler.get_jobs()} >= {
            COMPILE_JOB_ID,
            fetch_job_id("a"),
            fetch_job_id("b"),
        }
    finally:
        scheduler.shutdown()


def test_started_scheduler_survives_a_failing_job(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path, _exploding_factory)
    scheduler.start()
    try:
        assert scheduler.next_compile_at() is not None
        scheduler.scheduler.modify_job(fetch_job_id("a"), next_run_time=utcnow())
        deadline = time.monotonic() + WAIT
        while ("fetch", "a", "failed") not in _runs(tmp_path) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ("fetch", "a", "failed") in _runs(tmp_path)
        assert scheduler.scheduler.running
        assert {job.id for job in scheduler.scheduler.get_jobs()} == {
            COMPILE_JOB_ID,
            fetch_job_id("a"),
            fetch_job_id("b"),
        }
    finally:
        scheduler.shutdown()
    assert not scheduler.scheduler.running


def test_next_compile_at_is_none_until_started(tmp_path: Path) -> None:
    scheduler = _scheduler(tmp_path)
    assert scheduler.next_compile_at() is None


@pytest.mark.parametrize("pending", [True, False])
def test_debounce_keeps_the_hourly_compile(tmp_path: Path, pending: bool) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    if not pending:
        scheduler.start()
    try:
        scheduler.schedule_debounced_compile()
        scheduler.schedule_debounced_compile()
        ids = [job.id for job in scheduler.scheduler.get_jobs()]
        assert ids.count(DEBOUNCED_COMPILE_JOB_ID) == 1
        assert ids.count(COMPILE_JOB_ID) == 1
        if not pending:
            next_compile = scheduler.next_compile_at()
            assert next_compile is not None
            assert next_compile <= utcnow() + timedelta(minutes=2, seconds=5)
    finally:
        if not pending:
            scheduler.shutdown()


def test_a_future_last_attempt_is_capped_at_one_interval(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _seed(tmp_path)
    _set_last_attempt(tmp_path, "a", utcnow() + timedelta(days=3650))  # clock stepped back
    scheduler = _scheduler(tmp_path)
    with caplog.at_level("WARNING", logger="threatcull.web.scheduler"):
        scheduler.rescan()
    run_at = _next_runs(scheduler)[fetch_job_id("a")]
    assert run_at <= utcnow() + timedelta(minutes=60, seconds=60 * 60 // 10)
    assert any("in the future" in record.getMessage() for record in caplog.records)


def test_the_hourly_compile_job_rescans_for_sources_enabled_elsewhere(tmp_path: Path) -> None:
    """A Source enabled with the CLI while ``serve`` runs gets its Fetch job within the hour."""
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    assert fetch_job_id("c") not in _fetch_jobs(scheduler)
    _set_enabled(tmp_path, "c", True)  # e.g. `threatcull sources enable c`
    hourly = scheduler.scheduler.get_job(COMPILE_JOB_ID)
    assert hourly is not None
    hourly.func()
    assert fetch_job_id("c") in _fetch_jobs(scheduler)
    assert any(run_type == "compile" for run_type, _, _ in _runs(tmp_path))


def test_a_failing_rescan_does_not_stop_the_hourly_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)

    def broken_rescan() -> NoReturn:
        raise RuntimeError("rescan broke")

    monkeypatch.setattr(scheduler, "rescan", broken_rescan)
    hourly = scheduler.scheduler.get_job(COMPILE_JOB_ID)
    assert hourly is not None
    hourly.func()
    assert any(run_type == "compile" for run_type, _, _ in _runs(tmp_path))
