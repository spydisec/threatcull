# SPDX-License-Identifier: AGPL-3.0-only
"""PipelineRunner: Fetch + Compile, one run at a time, off the request thread.

Every run opens its own database connection (never a request's: a
``sqlite3.Connection`` must not be shared across threads) and closes it when
done. A non-blocking ``threading.Lock`` makes runs single-flight: a second
"Run now", or a Run now during a scheduled run, returns ``already_running``
straight away instead of queueing or crashing.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from threatcull.clock import ts, utcnow
from threatcull.compiling import compile_outputs
from threatcull.fetcher import Fetcher, HttpFetcher
from threatcull.fetching import fetch_all
from threatcull.web.deps import open_db

OUTPUTS_DIR = "outputs"

log = logging.getLogger(__name__)

RunStatus = Literal["ok", "blocked", "failed", "already_running"]


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


class PipelineRunner:
    """Runs the Plan 1 pipeline for the web app, never two at once."""

    def __init__(
        self, data_dir: Path, *, fetcher_factory: Callable[[], Fetcher] = HttpFetcher
    ) -> None:
        self._data_dir = data_dir
        self._fetcher_factory = fetcher_factory
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
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
            self._lock.release()

    def compile_only(self, *, force: bool = False) -> RunResult:
        """Compile without fetching (``force`` overrides a blocked Shrink Guard)."""
        if not self._lock.acquire(blocking=False):
            return ALREADY_RUNNING
        try:
            return self._run_locked(fetch=False, force=force)
        finally:
            self._lock.release()

    def start_background(self, force: bool = False) -> bool:
        """Start :meth:`run` in a daemon thread; ``False`` if a run is in progress.

        The lock is taken here, before the thread starts, so a second call
        straight after this one already sees the run as in progress.
        """
        if not self._lock.acquire(blocking=False):
            return False
        thread = threading.Thread(
            target=self._background, args=(force,), name="threatcull-run", daemon=True
        )
        try:
            thread.start()
        except BaseException:
            self._lock.release()
            raise
        self._thread = thread
        return True

    def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for a background run; ``True`` once idle."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                return False
        return not self.is_running()

    def _background(self, force: bool) -> None:
        try:
            self._run_locked(fetch=True, force=force)
        finally:
            self._lock.release()

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
