# SPDX-License-Identifier: AGPL-3.0-only
"""The built-in scheduler: periodic Fetches per Source and Compiles, off the request path.

One APScheduler interval job per enabled Source (its ``refresh_minutes``, with
up to 10% jitter so Sources don't all hit the network together), an hourly
Compile, and a debounced Compile two minutes after any successful Fetch
(a later Fetch pushes it back, so a burst of Fetches ends in one Compile).

Every job goes through the app's :class:`PipelineRunner`, so it shares the
"Run now" lock: if a run is in progress the job skips this tick at once and
the next interval tries again. Jobs never raise; the runner logs and records
failures as failed Runs, so the scheduler keeps all its jobs.
"""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from threatcull.clock import utcnow
from threatcull.store.sources import list_sources
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner

COMPILE_JOB_ID = "compile"
DEBOUNCED_COMPILE_JOB_ID = "compile-debounced"
COMPILE_INTERVAL = timedelta(minutes=60)
COMPILE_DEBOUNCE = timedelta(minutes=2)
JITTER_RATIO = 0.1
_FETCH_PREFIX = "fetch:"

log = logging.getLogger(__name__)


def fetch_job_id(source_id: str) -> str:
    return f"{_FETCH_PREFIX}{source_id}"


def _fetch_trigger(refresh_minutes: int) -> IntervalTrigger:
    jitter = int(refresh_minutes * 60 * JITTER_RATIO)
    return IntervalTrigger(minutes=refresh_minutes, jitter=jitter or None, timezone=UTC)


class Scheduler:
    """Owns the APScheduler instance and keeps its jobs in step with the Sources."""

    def __init__(self, data_dir: Path, runner: PipelineRunner) -> None:
        self.data_dir = data_dir
        self.runner = runner
        self.scheduler = BackgroundScheduler(
            timezone=UTC,
            # A missed tick (busy executor, suspended host) runs once, late,
            # rather than never or several times over.
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": None},
        )
        # rescan() runs on request threads and debounces on executor threads.
        self._lock = threading.Lock()
        self.scheduler.add_job(
            self.compile_job,
            IntervalTrigger(seconds=COMPILE_INTERVAL.total_seconds(), timezone=UTC),
            id=COMPILE_JOB_ID,
            name="Compile (hourly)",
        )

    def start(self) -> None:
        """Scan the Sources, then start the scheduler's background thread."""
        self.rescan()
        self.scheduler.start()

    def shutdown(self) -> None:
        """Stop without waiting for a running job (it finishes on its own thread)."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def rescan(self) -> None:
        """Add, update and remove per-Source Fetch jobs to match the enabled Sources."""
        conn = open_db(self.data_dir)
        try:
            wanted = {
                fetch_job_id(s.id): (s.id, s.refresh_minutes)
                for s in list_sources(conn, enabled_only=True)
            }
        finally:
            conn.close()
        with self._lock:
            existing = {
                job.id: job for job in self.scheduler.get_jobs() if job.id.startswith(_FETCH_PREFIX)
            }
            for job_id in existing.keys() - wanted.keys():
                self._remove(job_id)
            for job_id, (source_id, refresh_minutes) in wanted.items():
                trigger = _fetch_trigger(refresh_minutes)
                current = existing.get(job_id)
                if current is not None and _same_interval(current.trigger, trigger):
                    continue
                self._remove(job_id)
                self.scheduler.add_job(
                    self.fetch_job,
                    trigger,
                    args=(source_id,),
                    id=job_id,
                    name=f"Fetch {source_id}",
                )

    def fetch_job(self, source_id: str) -> None:
        """Fetch one Source; after a successful Fetch, (re)schedule the debounced Compile."""
        try:
            result = self.runner.run_source(source_id)
            if result.status == "already_running":
                log.info("Fetch of %s skipped: a run is in progress", source_id)
            elif result.status == "ok":
                self.schedule_debounced_compile()
        except Exception:
            # run_source never raises; this only guards the scheduler itself.
            log.exception("scheduled Fetch job for %s failed", source_id)

    def compile_job(self) -> None:
        try:
            result = self.runner.compile_only()
            if result.status == "already_running":
                log.info("scheduled Compile skipped: a run is in progress")
        except Exception:
            log.exception("scheduled Compile job failed")

    def schedule_debounced_compile(self) -> None:
        """Compile in two minutes, replacing any debounced Compile still pending."""
        with self._lock:
            self._remove(DEBOUNCED_COMPILE_JOB_ID)
            self.scheduler.add_job(
                self.compile_job,
                DateTrigger(run_date=utcnow() + COMPILE_DEBOUNCE, timezone=UTC),
                id=DEBOUNCED_COMPILE_JOB_ID,
                name="Compile (after Fetch)",
            )

    def next_compile_at(self) -> datetime | None:
        """When the next scheduled Compile runs; ``None`` if the scheduler isn't running."""
        if not self.scheduler.running:
            return None
        times = [
            job.next_run_time
            for job_id in (COMPILE_JOB_ID, DEBOUNCED_COMPILE_JOB_ID)
            if (job := self.scheduler.get_job(job_id)) is not None and job.next_run_time is not None
        ]
        return min(times, default=None)

    def _remove(self, job_id: str) -> None:
        with suppress(JobLookupError):
            self.scheduler.remove_job(job_id)


def _same_interval(current: object, wanted: IntervalTrigger) -> bool:
    return (
        isinstance(current, IntervalTrigger)
        and current.interval == wanted.interval
        and current.jitter == wanted.jitter
    )
