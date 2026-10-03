# SPDX-License-Identifier: AGPL-3.0-only
"""The built-in scheduler: periodic Fetches per Source and Compiles, off the request path.

One APScheduler interval job per enabled Source (its ``refresh_minutes``, with
up to 10% jitter so Sources don't all hit the network together), an hourly
Compile (which first rescans the Sources, catching changes made by the CLI),
and a debounced Compile two minutes after any successful (or not-modified)
Fetch; a later Fetch pushes it back, so a burst of Fetches ends in one Compile.

Timers survive restarts: a Source's first Fetch is due ``refresh_minutes``
after its last attempt, and Sources never fetched (or overdue) are fetched
within minutes of start-up, staggered so they don't all start together.

Every job goes through the app's :class:`PipelineRunner`, so it shares the
"Run now" lock. A job that finds a run in progress returns at once: a Fetch
arms a one-off retry in about three minutes (one per Source), a Compile
re-arms the debounced Compile. Jobs never raise; the runner logs and records
failures as failed Runs, so the scheduler keeps all its jobs.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import SystemRandom
from typing import Any
from urllib.parse import urlparse

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from threatcull.clock import utcnow
from threatcull.store.errors import NotFoundError
from threatcull.store.runs import last_run
from threatcull.store.sources import Source, get_source, list_sources
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner

COMPILE_JOB_ID = "compile"
DEBOUNCED_COMPILE_JOB_ID = "compile-debounced"
COMPILE_INTERVAL = timedelta(minutes=60)
COMPILE_DEBOUNCE = timedelta(minutes=2)
# First Compile after start-up when the last one is missing or over an hour old.
STARTUP_COMPILE_DELAY = timedelta(minutes=5)
JITTER_RATIO = 0.1
# Overdue / never-fetched Sources at start-up: the first after 30 s, then every 45 s.
OVERDUE_FIRST_DELAY = timedelta(seconds=30)
OVERDUE_STAGGER = timedelta(seconds=45)
# A Fetch tick that finds a run in progress retries after 3 min plus up to 30 s.
BUSY_RETRY_DELAY = timedelta(minutes=3)
BUSY_RETRY_JITTER_SECONDS = 30.0
# The network can come up after the container (a power cut where the Pi boots
# before the router): the first scheduled Fetch waits up to this long for DNS.
NETWORK_WAIT_SECONDS = 120.0
NETWORK_POLL_SECONDS = 2.0
_FETCH_PREFIX = "fetch:"
_RETRY_PREFIX = "fetch-retry:"

log = logging.getLogger(__name__)
_random = SystemRandom()  # jitter only; SystemRandom keeps the linters quiet


def resolves(host: str) -> bool:
    """True when ``host`` resolves (DNS works, or it is an IP literal)."""
    try:
        socket.getaddrinfo(host, None)
    except OSError:
        return False
    return True


def fetch_job_id(source_id: str) -> str:
    return f"{_FETCH_PREFIX}{source_id}"


def fetch_retry_job_id(source_id: str) -> str:
    return f"{_RETRY_PREFIX}{source_id}"


def _jitter_seconds(refresh_minutes: int) -> int:
    return int(refresh_minutes * 60 * JITTER_RATIO)


def _fetch_trigger(refresh_minutes: int) -> IntervalTrigger:
    jitter = _jitter_seconds(refresh_minutes)
    return IntervalTrigger(minutes=refresh_minutes, jitter=jitter or None, timezone=UTC)


def _due(source: Source, now: datetime) -> datetime:
    """When ``source`` is next due: ``refresh_minutes`` after its last attempt.

    Capped at one interval from ``now``: a last attempt in the future (the
    clock stepped back, e.g. a VM restore or an NTP correction) must not push
    the next Fetch out arbitrarily far.
    """
    if source.last_attempt_at is None:
        return now
    last = datetime.fromisoformat(source.last_attempt_at)
    if last > now:
        log.warning(
            "Source %s last attempt %s is in the future (clock skew?); "
            "scheduling its next Fetch one interval from now",
            source.id,
            source.last_attempt_at,
        )
    interval = timedelta(minutes=source.refresh_minutes)
    return min(last + interval, now + interval)


def _next_run_time(job: Any) -> datetime | None:
    """A job's next run; ``None`` if it has none (a pending job may lack the attribute)."""
    run_at: datetime | None = getattr(job, "next_run_time", None)
    return run_at


class Scheduler:
    """Owns the APScheduler instance and keeps its jobs in step with the Sources."""

    def __init__(
        self,
        data_dir: Path,
        runner: PipelineRunner,
        *,
        resolve: Callable[[str], bool] = resolves,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.data_dir = data_dir
        self.runner = runner
        self._resolve = resolve
        self._sleep = sleep
        self._monotonic = monotonic
        # Set once the first scheduled Fetch has waited for DNS (or found it working).
        self._network_checked = False
        self._network_lock = threading.Lock()
        self.scheduler = BackgroundScheduler(
            timezone=UTC,
            # A missed tick (busy executor, suspended host) runs once, late,
            # rather than never or several times over.
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": None},
        )
        # rescan() runs on request threads and debounces on executor threads.
        self._lock = threading.Lock()
        self._add_compile_job()

    def start(self) -> None:
        """Scan the Sources, time the first Compile, then start the background thread."""
        self.rescan()
        now = utcnow()
        conn = open_db(self.data_dir)
        try:
            last = last_run(conn, "compile")
        finally:
            conn.close()
        first = now + STARTUP_COMPILE_DELAY
        if last is not None:
            follows = datetime.fromisoformat(last.started_at) + COMPILE_INTERVAL
            if follows > now:
                first = follows
        with self._lock:
            self._remove(COMPILE_JOB_ID)
            self._add_compile_job(next_run_time=first)
        self.scheduler.start()

    def shutdown(self) -> None:
        """Stop the scheduler without waiting for a running job.

        ``shutdown(wait=False)`` returns at once, but a Fetch or Compile
        already running keeps going on its executor thread, and the
        interpreter may still wait for it to finish when the process exits.
        """
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def rescan(self, *, catch_up: bool = True) -> None:
        """Add, update and remove per-Source Fetch jobs to match the enabled Sources.

        Jobs whose interval is unchanged are left alone (their timing too), so
        calling this again is harmless. A new or changed job's first run is
        ``refresh_minutes`` after the Source's last attempt (plus jitter).
        When that is already past (never fetched, or overdue):

        - ``catch_up=True`` (start-up) fetches within minutes, staggered in due
          order, so a restart after downtime catches up;
        - ``catch_up=False`` (a Source enabled in the UI, the API, the CLI or a
          Catalog update) waits for the regular schedule: one interval from
          now, at most an hour. Enabling several Sources in a row then starts
          no Fetches; Run now fetches them all at once.
        """
        conn = open_db(self.data_dir)
        try:
            wanted = {fetch_job_id(s.id): s for s in list_sources(conn, enabled_only=True)}
        finally:
            conn.close()
        now = utcnow()
        with self._lock:
            jobs = self.scheduler.get_jobs()
            existing = {job.id: job for job in jobs if job.id.startswith(_FETCH_PREFIX)}
            for job_id in existing.keys() - wanted.keys():
                self._remove(job_id)
            wanted_retries = {fetch_retry_job_id(s.id) for s in wanted.values()}
            for job in jobs:
                if job.id.startswith(_RETRY_PREFIX) and job.id not in wanted_retries:
                    self._remove(job.id)
            to_add = [
                (job_id, source)
                for job_id, source in wanted.items()
                if not (
                    (current := existing.get(job_id)) is not None
                    and _same_interval(current.trigger, _fetch_trigger(source.refresh_minutes))
                )
            ]
            overdue = 0
            dues = {job_id: _due(source, now) for job_id, source in to_add}
            for job_id, source in sorted(to_add, key=lambda item: dues[item[0]]):
                due = dues[job_id]
                if due <= now and catch_up:
                    first = now + OVERDUE_FIRST_DELAY + overdue * OVERDUE_STAGGER
                    overdue += 1
                elif due <= now:
                    # Spread new Sources out, but never past the hour: the jitter is
                    # taken off the wait, not added to it.
                    wait = min(timedelta(minutes=source.refresh_minutes), COMPILE_INTERVAL)
                    jitter = min(_jitter_seconds(source.refresh_minutes), wait.total_seconds())
                    first = now + wait - timedelta(seconds=_random.uniform(0, jitter))
                else:
                    jitter = _jitter_seconds(source.refresh_minutes)
                    first = due + timedelta(seconds=_random.uniform(0, jitter))
                self._remove(job_id)
                self.scheduler.add_job(
                    self.fetch_job,
                    _fetch_trigger(source.refresh_minutes),
                    args=(source.id,),
                    id=job_id,
                    name=f"Fetch {source.id}",
                    next_run_time=first,
                )

    def source_changed(self) -> None:
        """The app's hook for a Source change: rescan without catching up."""
        self.rescan(catch_up=False)

    def next_fetch_times(self) -> dict[str, datetime]:
        """When each enabled Source is fetched next (its job or a pending retry)."""
        times: dict[str, datetime] = {}
        with self._lock:
            jobs = self.scheduler.get_jobs()
        for job in jobs:
            for prefix in (_FETCH_PREFIX, _RETRY_PREFIX):
                if job.id.startswith(prefix) and (run_at := _next_run_time(job)) is not None:
                    source_id = job.id.removeprefix(prefix)
                    if source_id not in times or run_at < times[source_id]:
                        times[source_id] = run_at
        return times

    def retries_waiting(self) -> int:
        """Fetches that found a run in progress and wait to try again."""
        with self._lock:
            return sum(1 for job in self.scheduler.get_jobs() if job.id.startswith(_RETRY_PREFIX))

    def fetch_job(self, source_id: str) -> None:
        """Fetch one Source (regular tick or busy retry); then debounce a Compile."""
        try:
            self._await_network(source_id)
            result = self.runner.run_source(source_id)
            if result.status == "already_running":
                log.info("Fetch of %s deferred: a run is in progress", source_id)
                self._arm_retry(source_id)
                return
            with self._lock:
                self._remove(fetch_retry_job_id(source_id))  # this Fetch covers it
            if result.status in ("ok", "not_modified"):
                # not_modified too: it refreshes last_seen and can revive a Stale Source.
                self.schedule_debounced_compile()
        except Exception:
            # run_source never raises; this only guards the scheduler itself.
            log.exception("scheduled Fetch job for %s failed", source_id)

    def _await_network(self, source_id: str) -> None:
        """Before the first scheduled Fetch since start-up, wait until DNS resolves.

        Waits at most ``NETWORK_WAIT_SECONDS``, then fetches anyway (a real
        failure is then recorded as usual). Fetches queued behind the first one
        wait on the same lock instead of failing one by one.
        """
        if self._network_checked:
            return
        with self._network_lock:
            if self._network_checked:
                return
            host = self._source_host(source_id)
            if host is None:
                return  # a file:// Source needs no network; the next one checks
            deadline = self._monotonic() + NETWORK_WAIT_SECONDS
            while not self._resolve(host):
                if self._monotonic() >= deadline:
                    log.warning(
                        "DNS for %s still fails after %.0f s; fetching anyway",
                        host,
                        NETWORK_WAIT_SECONDS,
                    )
                    break
                self._sleep(NETWORK_POLL_SECONDS)
            self._network_checked = True

    def _source_host(self, source_id: str) -> str | None:
        """The host an http(s) Source is fetched from, else ``None``."""
        conn = open_db(self.data_dir)
        try:
            url = get_source(conn, source_id).url
        except NotFoundError:
            return None
        finally:
            conn.close()
        parsed = urlparse(url)
        return parsed.hostname if parsed.scheme in ("http", "https") else None

    def compile_job(self) -> None:
        try:
            result = self.runner.compile_only()
            if result.status == "already_running":
                log.info("scheduled Compile deferred: a run is in progress")
                self.schedule_debounced_compile()
        except Exception:
            log.exception("scheduled Compile job failed")

    def hourly_job(self) -> None:
        """Rescan the Sources, then Compile.

        The rescan picks up Sources enabled or disabled outside the web UI
        (e.g. ``threatcull sources enable`` while ``serve`` runs) within the hour.
        """
        try:
            self.rescan(catch_up=False)
        except Exception:
            log.exception("hourly rescan of the Sources failed")
        self.compile_job()

    def schedule_debounced_compile(self) -> None:
        """Compile in two minutes, replacing any debounced Compile still pending."""
        run_at = utcnow() + COMPILE_DEBOUNCE
        with self._lock:
            self._remove(DEBOUNCED_COMPILE_JOB_ID)
            self.scheduler.add_job(
                self.compile_job,
                DateTrigger(run_date=run_at, timezone=UTC),
                id=DEBOUNCED_COMPILE_JOB_ID,
                name="Compile (after Fetch)",
                next_run_time=run_at,
            )

    def _arm_retry(self, source_id: str) -> None:
        """One pending retry per Source, unless its regular tick comes sooner.

        The regular interval job is never moved from inside a job; the retry
        is a separate one-off job that runs :meth:`fetch_job` again (and so
        re-arms itself while the runner stays busy).
        """
        retry_at = utcnow() + BUSY_RETRY_DELAY
        retry_at += timedelta(seconds=_random.uniform(0, BUSY_RETRY_JITTER_SECONDS))
        with self._lock:
            regular = self.scheduler.get_job(fetch_job_id(source_id))
            regular_at = _next_run_time(regular) if regular is not None else None
            if regular_at is not None and regular_at <= retry_at:
                return
            self._remove(fetch_retry_job_id(source_id))
            self.scheduler.add_job(
                self.fetch_job,
                DateTrigger(run_date=retry_at, timezone=UTC),
                args=(source_id,),
                id=fetch_retry_job_id(source_id),
                name=f"Fetch {source_id} (retry)",
                next_run_time=retry_at,
            )

    def next_compile_at(self) -> datetime | None:
        """When the next scheduled Compile runs; ``None`` if the scheduler isn't running."""
        if not self.scheduler.running:
            return None
        times = [
            job.next_run_time
            for job_id in (COMPILE_JOB_ID, DEBOUNCED_COMPILE_JOB_ID)
            if (job := self.scheduler.get_job(job_id)) is not None
            and _next_run_time(job) is not None
        ]
        return min(times, default=None)

    def _add_compile_job(self, **kwargs: Any) -> None:
        self.scheduler.add_job(
            self.hourly_job,
            IntervalTrigger(seconds=COMPILE_INTERVAL.total_seconds(), timezone=UTC),
            id=COMPILE_JOB_ID,
            name="Compile (hourly)",
            **kwargs,
        )

    def _remove(self, job_id: str) -> None:
        with suppress(JobLookupError):
            self.scheduler.remove_job(job_id)


def _same_interval(current: object, wanted: IntervalTrigger) -> bool:
    return (
        isinstance(current, IntervalTrigger)
        and current.interval == wanted.interval
        and current.jitter == wanted.jitter
    )
