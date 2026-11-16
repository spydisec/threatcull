# SPDX-License-Identifier: AGPL-3.0-only
"""The run status view (#58): what runs, since when, what comes next."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.factories import make_entry
from threatcull.clock import ts
from threatcull.store.runs import finish_run, previous_duration, runs_after, start_run
from threatcull.store.sources import sync_catalog
from threatcull.web.jobs import ActiveRun, PipelineRunner
from threatcull.web.status import build_status
from threatcull.web.templating import _duration


@pytest.fixture
def seeded(conn: sqlite3.Connection) -> sqlite3.Connection:
    sync_catalog(
        conn,
        [
            make_entry(id="a", url="https://a.example/1", default_enabled=True, name="Source A"),
            make_entry(id="b", url="https://b.example/1", default_enabled=True, name="Source B"),
        ],
    )
    return conn


class _BusyRunner(PipelineRunner):
    """A runner that reports ``active`` as running without a real run."""

    def __init__(self, data_dir: Path, active: ActiveRun | None) -> None:
        super().__init__(data_dir)
        self.active = active

    def is_running(self) -> bool:
        return self.active is not None


def test_idle_status_lists_unpublished_outputs(seeded: sqlite3.Connection, tmp_path: Path) -> None:
    status = build_status(seeded, _BusyRunner(tmp_path, None), None)
    assert status.running is False
    assert status.scheduler_on is False


def test_fetch_step_names_source_position_and_previous_duration(
    seeded: sqlite3.Connection, tmp_path: Path, now: datetime
) -> None:
    earlier = start_run(seeded, "fetch", now=now - timedelta(hours=1), source_id="b")
    finish_run(seeded, earlier, "ok", now=now - timedelta(hours=1) + timedelta(seconds=95))
    run_start = ts(now)
    mark = earlier  # the highest Run id when Run now began
    first = start_run(seeded, "fetch", now=now, source_id="a")
    finish_run(seeded, first, "ok", now=now + timedelta(seconds=5))
    start_run(seeded, "fetch", now=now + timedelta(seconds=5), source_id="b")
    runner = _BusyRunner(tmp_path, ActiveRun("run_now", run_start, fetch=True, after_run_id=mark))
    status = build_status(seeded, runner, None, now=now + timedelta(seconds=35))
    assert (status.step, status.source_id, status.source_name) == ("fetch", "b", "Source B")
    assert (status.position, status.total) == (2, 2)
    assert status.elapsed_seconds == 30
    assert status.previous_seconds == 95
    assert status.trigger_label == "Run now"


def test_compile_step_started_by_the_schedule(
    seeded: sqlite3.Connection, tmp_path: Path, now: datetime
) -> None:
    start_run(seeded, "compile", now=now)
    runner = _BusyRunner(tmp_path, ActiveRun("scheduled_compile", ts(now), fetch=False))
    status = build_status(seeded, runner, None, now=now + timedelta(minutes=2))
    assert (status.step, status.position, status.elapsed_seconds) == ("compile", None, 120)
    assert status.trigger_label == "the schedule"


def test_running_before_the_first_step_row(
    seeded: sqlite3.Connection, tmp_path: Path, now: datetime
) -> None:
    runner = _BusyRunner(tmp_path, ActiveRun("force_compile", ts(now), fetch=False))
    status = build_status(seeded, runner, None, now=now)
    assert status.running is True
    assert status.step is None


def test_previous_duration_ignores_zero_length_history(
    conn: sqlite3.Connection, now: datetime
) -> None:
    old = start_run(conn, "compile", now=now)
    conn.execute("UPDATE runs SET finished_at = started_at, status = 'ok' WHERE id = ?", (old,))
    current = start_run(conn, "compile", now=now + timedelta(hours=1))
    assert previous_duration(conn, "compile", source_id=None, before_id=current) is None


def test_runs_after_counts_only_that_type(conn: sqlite3.Connection, now: datetime) -> None:
    mark = start_run(conn, "fetch", now=now, source_id="old")
    start_run(conn, "fetch", now=now, source_id="a")
    start_run(conn, "compile", now=now)
    assert runs_after(conn, "fetch", mark) == 1


def test_a_running_row_from_an_earlier_run_is_not_the_current_step(
    seeded: sqlite3.Connection, tmp_path: Path, now: datetime
) -> None:
    # An interrupted run left its row "running", in the same second the new run began.
    leftover = start_run(seeded, "fetch", now=now, source_id="a")
    runner = _BusyRunner(tmp_path, ActiveRun("run_now", ts(now), fetch=True, after_run_id=leftover))
    status = build_status(seeded, runner, None, now=now)
    assert status.running is True
    assert status.step is None  # the new run hasn't written its first row yet


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (None, ""),
        (0, "0 s"),
        (0.4, "<1 s"),
        (2.6, "3 s"),
        (45, "45 s"),
        (60, "1 min"),
        (200, "3 min 20 s"),
        (3900, "1 h 5 min"),
    ],
)
def test_duration_filter(seconds: float | None, text: str) -> None:
    assert _duration(seconds) == text
