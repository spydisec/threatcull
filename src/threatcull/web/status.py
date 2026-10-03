# SPDX-License-Identifier: AGPL-3.0-only
"""What ThreatCull is doing right now: the run status line and ``GET /api/v1/status``.

Built from three places: the runner (what started the run in progress), the
``runs`` table (which step is running, since when, how long it took last time)
and the scheduler (what comes next).
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from threatcull.clock import ts, utcnow
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import list_outputs
from threatcull.store.runs import previous_duration, running_run, runs_after
from threatcull.store.sources import get_source, list_sources
from threatcull.web.jobs import PipelineRunner
from threatcull.web.scheduler import Scheduler

TRIGGER_LABELS = {
    "run_now": "Run now",
    "force_compile": "Force Compile",
    "scheduled_fetch": "the schedule",
    "scheduled_compile": "the schedule",
}


@dataclass(frozen=True, slots=True)
class NextFetch:
    source_id: str
    source_name: str
    at: str


@dataclass(frozen=True, slots=True)
class StatusView:
    running: bool
    trigger: str | None = None  # run_now, force_compile, scheduled_fetch, scheduled_compile
    run_started_at: str | None = None
    step: str | None = None  # "fetch" or "compile"
    step_started_at: str | None = None
    elapsed_seconds: int | None = None
    previous_seconds: int | None = None  # the same step's last duration, as a guide
    source_id: str | None = None
    source_name: str | None = None
    position: int | None = None  # "Fetching 3 of 10" during Run now
    total: int | None = None
    scheduler_on: bool = False
    next_compile_at: str | None = None
    next_fetch: NextFetch | None = None
    retries_waiting: int = 0
    unpublished_outputs: list[str] = field(default_factory=list)

    @property
    def trigger_label(self) -> str | None:
        return TRIGGER_LABELS.get(self.trigger or "")

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def build_status(
    conn: sqlite3.Connection,
    runner: PipelineRunner,
    scheduler: Scheduler | None,
    *,
    now: datetime | None = None,
) -> StatusView:
    now = now or utcnow()
    active = runner.active if runner.is_running() else None
    names = {source.id: source.name for source in list_sources(conn)}
    unpublished = [o.name for o in list_outputs(conn) if o.last_published_at is None]
    upcoming = _upcoming(scheduler, names)
    if active is None:
        return StatusView(running=False, unpublished_outputs=unpublished, **upcoming)
    step = running_run(conn, after_id=active.after_run_id)
    if step is None:
        # The lock is held but the first step hasn't written its row yet.
        return StatusView(
            running=True,
            trigger=active.trigger,
            run_started_at=active.started_at,
            unpublished_outputs=unpublished,
            **upcoming,
        )
    started = datetime.fromisoformat(step.started_at)
    position = total = None
    if step.type == "fetch" and active.trigger == "run_now":
        total = sum(1 for source in list_sources(conn, enabled_only=True))
        position = runs_after(conn, "fetch", active.after_run_id)
    return StatusView(
        running=True,
        trigger=active.trigger,
        run_started_at=active.started_at,
        step=step.type,
        step_started_at=step.started_at,
        elapsed_seconds=max(0, int((now - started).total_seconds())),
        previous_seconds=previous_duration(
            conn, step.type, source_id=step.source_id, before_id=step.id
        ),
        source_id=step.source_id,
        source_name=_source_name(conn, step.source_id, names),
        position=position,
        total=total,
        unpublished_outputs=unpublished,
        **upcoming,
    )


def _source_name(
    conn: sqlite3.Connection, source_id: str | None, names: dict[str, str]
) -> str | None:
    if source_id is None:
        return None
    if source_id in names:
        return names[source_id]
    try:
        return get_source(conn, source_id).name
    except NotFoundError:
        return source_id


def _upcoming(scheduler: Scheduler | None, names: dict[str, str]) -> dict[str, Any]:
    if scheduler is None or not scheduler.scheduler.running:
        return {"scheduler_on": False}
    compile_at = scheduler.next_compile_at()
    fetches = scheduler.next_fetch_times()
    next_fetch = None
    if fetches:
        source_id, at = min(fetches.items(), key=lambda item: item[1])
        next_fetch = NextFetch(source_id, names.get(source_id, source_id), ts(at))
    return {
        "scheduler_on": True,
        "next_compile_at": ts(compile_at) if compile_at is not None else None,
        "next_fetch": next_fetch,
        "retries_waiting": scheduler.retries_waiting(),
    }
