# SPDX-License-Identifier: AGPL-3.0-only
"""PipelineRunner: Fetch + Compile, one run at a time, off the request thread.

Every run opens its own database connection (never a request's: a
``sqlite3.Connection`` must not be shared across threads) and closes it when
done. A non-blocking ``threading.Lock`` makes runs single-flight: a second
"Run now", or a Run now during a scheduled run, returns ``already_running``
straight away instead of queueing or crashing. The scheduler's per-Source
Fetches (:meth:`PipelineRunner.run_source`) take the same lock.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread
from typing import Literal

from threatcull.clock import ts, utcnow
from threatcull.compiling import compile_outputs
from threatcull.fetcher import Fetcher, HttpFetcher
from threatcull.fetching import fetch_all, fetch_source
from threatcull.store.errors import NotFoundError
from threatcull.store.runs import fail_unfinished_runs, finish_run, latest_run_id, start_run
from threatcull.store.sightings import record_fetch_failure
from threatcull.store.sources import get_source
from threatcull.web.deps import open_db

OUTPUTS_DIR = "outputs"

log = logging.getLogger(__name__)

RunStatus = Literal["ok", "not_modified", "blocked", "failed", "already_running", "skipped"]


@dataclass(frozen=True, slots=True)
class RunResult:
    """What one PipelineRunner run did, for the UI (the Runs table has the history)."""

    status: RunStatus
    fetched: int = 0
    failed_sources: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    reasons: tuple[str, ...] = ()
    error: str | None = None
    finished_at: str | None = None


ALREADY_RUNNING = RunResult("already_running")
SKIPPED = RunResult("skipped")


class PipelineRunner:
    """Runs the Plan 1 pipeline for the web app, never two at once."""

    def __init__(
        self, data_dir: Path, *, fetcher_factory: Callable[[], Fetcher] = HttpFetcher
    ) -> None:
        self._data_dir = data_dir
        self._fetcher_factory = fetcher_factory
        self._lock = threading.Lock()
        # Notified whenever the lock is released, so wait() wakes up however
        # the run was started (background thread, or a synchronous caller).
        self._idle = threading.Condition()
        self.last_result: RunResult | None = None

    def is_running(self) -> bool:
        return self._lock.locked()

    def run(self, *, force: bool = False) -> RunResult:
        """Fetch every enabled Source, then Compile; ``already_running`` if busy."""
        if not self._lock.acquire(blocking=False):
            return ALREADY_RUNNING
        try:
            return self._run_locked(fetch=True, force=force)
        finally:
            self._release()

    def compile_only(self, *, force: bool = False) -> RunResult:
        """Compile without fetching (``force`` overrides a blocked Shrink Guard)."""
        if not self._lock.acquire(blocking=False):
            return ALREADY_RUNNING
        try:
            return self._run_locked(fetch=False, force=force)
        finally:
            self._release()

    def run_source(self, source_id: str) -> RunResult:
        """Fetch one Source (the scheduler's per-Source job); no Compile.

        ``already_running`` straight away if another run holds the lock (the
        scheduler skips that tick), ``skipped`` if the Source is gone or
        disabled by now. Never raises: a crash is logged and recorded as a
        failed Fetch Run. Does not touch :attr:`last_result`, which is the
        last whole pipeline run.
        """
        if not self._lock.acquire(blocking=False):
            return ALREADY_RUNNING
        try:
            return self._fetch_one_locked(source_id)
        finally:
            self._release()

    def start_background(self, force: bool = False) -> bool:
        """Start :meth:`run` in a daemon thread; ``False`` if a run is in progress.

        The lock is taken here, before the thread starts, so a second call
        straight after this one already sees the run as in progress.
        """
        if not self._lock.acquire(blocking=False):
            return False
        try:
            thread = Thread(
                target=self._background, args=(force,), name="threatcull-run", daemon=True
            )
            thread.start()
        except BaseException:
            self._release()
            raise
        return True

    def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds until no run holds the lock; ``True`` once idle.

        Covers every kind of run: a background one, a synchronous
        ``run``/``compile_only``/``run_source`` on another thread, or none.
        """
        with self._idle:
            return self._idle.wait_for(lambda: not self._lock.locked(), timeout)

    def _release(self) -> None:
        with self._idle:
            self._lock.release()
            self._idle.notify_all()

    def _background(self, force: bool) -> None:
        try:
            self._run_locked(fetch=True, force=force)
        finally:
            self._release()

    def _fetch_one_locked(self, source_id: str) -> RunResult:
        """One Source's Fetch; the caller holds the lock. Never raises."""
        mark: int | None = None  # Runs above this id were started by this call
        try:
            conn = open_db(self._data_dir)
            try:
                mark = latest_run_id(conn)
                try:
                    source = get_source(conn, source_id)
                except NotFoundError:
                    return SKIPPED
                if not source.enabled:
                    return SKIPPED
                outcome = fetch_source(conn, source, self._fetcher_factory(), now=utcnow())
            finally:
                conn.close()
        except Exception as exc:
            log.exception("scheduled Fetch of %s failed", source_id)
            error = f"{type(exc).__name__}: {exc}"
            self._record_failed_fetch(source_id, error, mark)
            return RunResult(
                "failed", failed_sources=(source_id,), error=error, finished_at=ts(utcnow())
            )
        if outcome.status == "failed":
            return RunResult(
                "failed",
                fetched=1,
                failed_sources=(source_id,),
                error=outcome.error,
                finished_at=ts(utcnow()),
            )
        return RunResult(outcome.status, fetched=1, finished_at=ts(utcnow()))

    def _record_failed_fetch(self, source_id: str, error: str, mark: int | None) -> None:
        """Best effort: a crash outside ``fetch_source`` still shows up in the Runs.

        ``mark`` is the highest Run id before this Fetch began (``None`` if it
        crashed before reading it): a "running" Fetch Run of this Source above
        it is the one fetch_source started, so that row is closed. Anything
        older is left to the start-up sweep.
        """
        try:
            conn = open_db(self._data_dir)
            try:
                now = utcnow()
                closed = 0
                if mark is not None:
                    closed = fail_unfinished_runs(
                        conn, "fetch", source_id=source_id, started_after=mark, now=now, error=error
                    )
                if not closed:
                    run_id = start_run(conn, "fetch", now=now, source_id=source_id)
                    finish_run(conn, run_id, "failed", now=now, error=error)
                record_fetch_failure(conn, source_id, error, now=now)
            finally:
                conn.close()
        except Exception:
            log.exception("could not record the failed Fetch of %s", source_id)

    def _run_locked(self, *, fetch: bool, force: bool) -> RunResult:
        """The run itself; the caller holds the lock. Never raises."""
        fetched = 0
        failed: tuple[str, ...] = ()
        try:
            conn = open_db(self._data_dir)
            try:
                if fetch:
                    outcomes = fetch_all(conn, self._fetcher_factory(), now=utcnow())
                    fetched = len(outcomes)
                    failed = tuple(o.source_id for o in outcomes if o.status == "failed")
                # Compile even after failed Fetches: those Sources keep their Sightings.
                report = compile_outputs(
                    conn, self._data_dir / OUTPUTS_DIR, now=utcnow(), force=force
                )
            finally:
                conn.close()
        except Exception as exc:
            # compile_outputs has already recorded a failed Run where it got that far.
            log.exception("pipeline run failed")
            result = RunResult(
                "failed",
                fetched=fetched,
                failed_sources=failed,
                error=f"{type(exc).__name__}: {exc}",
                finished_at=ts(utcnow()),
            )
        else:
            result = RunResult(
                report.status,
                fetched=fetched,
                failed_sources=failed,
                counts=dict(report.counts),
                reasons=report.reasons,
                finished_at=ts(utcnow()),
            )
        self.last_result = result
        return result
