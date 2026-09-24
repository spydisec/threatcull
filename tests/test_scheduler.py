# SPDX-License-Identifier: AGPL-3.0-only
"""The built-in scheduler: one Fetch job per enabled Source, hourly + debounced Compile.

Nothing here sleeps for real minutes: most tests build the scheduler without
starting it and call the job functions directly; the one started scheduler
fires a job "now" and every wait on it is bounded.
"""

import time
from datetime import timedelta
from pathlib import Path

import pytest
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.fetcher import Fetcher, FetchResult
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.runs import recent_runs
from threatcull.store.sources import set_enabled, sync_catalog
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner
from threatcull.web.scheduler import (
    COMPILE_JOB_ID,
    DEBOUNCED_COMPILE_JOB_ID,
    Scheduler,
    fetch_job_id,
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


def test_fetch_job_skips_quietly_while_the_runner_is_busy(tmp_path: Path) -> None:
    _seed(tmp_path)
    scheduler = _scheduler(tmp_path)
    scheduler.rescan()
    runner = scheduler.runner
    assert runner._lock.acquire(blocking=False)  # a "Run now" holds the lock
    try:
        started = time.monotonic()
        scheduler.fetch_job("a")
        scheduler.compile_job()
        assert time.monotonic() - started < 1.0
    finally:
        runner._lock.release()
    assert _runs(tmp_path) == []


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
