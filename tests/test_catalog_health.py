# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx

from tests.factories import make_entry
from threatcull.fetcher import FetchError, FetchResult

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "catalog_health", ROOT / "scripts" / "catalog_health.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["catalog_health"] = module
    spec.loader.exec_module(module)
    return module


ch = _load()

DAY = date(2026, 10, 12)
FEED = make_entry(id="feed", url="https://feeds.example/a.txt")
VENDOR = make_entry(
    id="vendor", url="https://vendor.example/ips", role="allowlist", category="infrastructure"
)


def _serve(**bodies: str | Exception) -> object:
    """A fetcher answering each URL's host part (``feeds``, ``vendor``) with text or an error."""

    def fetch(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        body = bodies[url.split("//")[1].split(".", maxsplit=1)[0]]
        if isinstance(body, Exception):
            raise body
        return FetchResult("ok", body, content_type="text/plain")

    return fetch


def _run(
    state: dict[str, Any], day: date, **bodies: str | Exception
) -> tuple[dict[str, Any], list[Any]]:
    new_state, problems, _skipped = ch.check([FEED, VENDOR], state, _serve(**bodies), day)
    return new_state, problems


def test_the_first_run_seeds_every_source_with_today() -> None:
    state, problems = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    assert problems == []
    assert state["feed"].last_changed == "2026-10-12"
    assert state["feed"].valid == 1
    assert state["feed"].failures == 0


def test_a_changed_list_moves_last_changed() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    later = DAY + timedelta(days=7)
    state, _ = _run(state, later, feeds="45.9.20.2\n", vendor="45.9.21.0/24\n")
    assert state["feed"].last_changed == "2026-10-19"


def test_reordered_entries_keep_last_changed() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n45.9.20.2\n", vendor="45.9.21.0/24\n")
    state, _ = _run(
        state, DAY + timedelta(days=7), feeds="45.9.20.2\n45.9.20.1\n", vendor="45.9.21.0/24\n"
    )
    assert state["feed"].last_changed == "2026-10-12"


def test_a_blocklist_unchanged_for_30_days_is_frozen() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    _, problems = _run(
        state, DAY + timedelta(days=29), feeds="45.9.20.1\n", vendor="45.9.21.0/24\n"
    )
    assert problems == []
    _, problems = _run(
        state, DAY + timedelta(days=30), feeds="45.9.20.1\n", vendor="45.9.21.0/24\n"
    )
    assert [(p.source_id, p.problem, p.since) for p in problems] == [
        ("feed", "frozen", "2026-10-12")
    ]


def test_allowlist_sources_are_never_frozen() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    _, problems = _run(
        state, DAY + timedelta(days=400), feeds="45.9.20.9\n", vendor="45.9.21.0/24\n"
    )
    assert all(p.source_id != "vendor" for p in problems)


def test_one_failure_is_not_reported_two_are() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    week = DAY + timedelta(days=7)
    state, problems = _run(state, week, feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n")
    assert problems == []
    _, problems = _run(
        state, week + timedelta(days=7), feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n"
    )
    assert [(p.source_id, p.problem, p.since, p.detail) for p in problems] == [
        ("feed", "dead", "2026-10-19", "HTTP 503")
    ]


def test_a_rerun_in_the_same_week_does_not_count_a_second_failure() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    week = DAY + timedelta(days=7)
    for extra in (0, 0, 1, 5):  # re-run the same day, then manual runs later that week
        state, problems = _run(
            state,
            week + timedelta(days=extra),
            feeds=FetchError(f"HTTP 503 day {extra}"),
            vendor="45.9.21.0/24\n",
        )
        assert problems == []
        assert state["feed"].failures == 1
    assert state["feed"].last_error == "HTTP 503 day 5"
    _, problems = _run(
        state, week + timedelta(days=7), feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n"
    )
    assert [(p.source_id, p.problem, p.since) for p in problems] == [("feed", "dead", "2026-10-19")]


def test_a_frozen_blocklist_stays_frozen_through_one_failure() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    month = DAY + timedelta(days=30)
    state, problems = _run(state, month, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    assert [p.problem for p in problems] == ["frozen"]
    state, problems = _run(
        state, month + timedelta(days=7), feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n"
    )
    assert [(p.source_id, p.problem, p.since) for p in problems] == [
        ("feed", "frozen", "2026-10-12")
    ]
    _, problems = _run(
        state, month + timedelta(days=14), feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n"
    )
    assert [p.problem for p in problems] == ["dead"]


def test_a_failing_source_keeps_its_change_date_and_first_failure() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    for weeks in (1, 2, 3):
        state, problems = _run(
            state,
            DAY + timedelta(days=7 * weeks),
            feeds=FetchError("HTTP 404"),
            vendor="45.9.21.0/24\n",
        )
    assert state["feed"].last_changed == "2026-10-12"
    assert state["feed"].failing_since == "2026-10-19"
    assert [p.problem for p in problems] == ["dead"]


def test_a_source_that_never_worked_is_reported_dead() -> None:
    state, _ = _run({}, DAY, feeds=FetchError("ConnectError"), vendor="45.9.21.0/24\n")
    _, problems = _run(
        state, DAY + timedelta(days=7), feeds=FetchError("ConnectError"), vendor="45.9.21.0/24\n"
    )
    assert [(p.source_id, p.problem, p.since) for p in problems] == [("feed", "dead", "2026-10-12")]


def test_html_and_empty_count_as_failures() -> None:
    state, _ = _run({}, DAY, feeds="<html>gone</html>", vendor="# nothing here\n")
    _, problems = _run(
        state, DAY + timedelta(days=7), feeds="<html>gone</html>", vendor="# nothing here\n"
    )
    details = {p.source_id: p.detail for p in problems}
    assert details["feed"] == "HTML page, not a list"
    assert details["vendor"].startswith("0 valid entries")


def test_recovery_clears_the_failure() -> None:
    state, _ = _run({}, DAY, feeds=FetchError("HTTP 503"), vendor="45.9.21.0/24\n")
    state, _ = _run(state, DAY + timedelta(days=7), feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    assert (state["feed"].failures, state["feed"].failing_since, state["feed"].last_error) == (
        0,
        None,
        None,
    )


def test_a_source_removed_from_the_catalog_is_dropped() -> None:
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    state["gone"] = ch.Record(last_changed="2025-01-01")
    state, _ = _run(state, DAY + timedelta(days=7), feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    assert set(state) == {"feed", "vendor"}


def test_state_round_trips_and_a_missing_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    assert ch.load_state(path) == {}
    state, _ = _run({}, DAY, feeds="45.9.20.1\n", vendor="45.9.21.0/24\n")
    ch.save_state(path, state)
    assert ch.load_state(path) == state
    assert path.read_text(encoding="utf-8").endswith("}\n")


def test_load_state_tolerates_missing_and_extra_keys(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"feed": {"last_changed": "2026-01-01", "future": 1}}))
    assert ch.load_state(path) == {"feed": ch.Record(last_changed="2026-01-01")}


def test_render_lists_problems_and_the_run() -> None:
    problem = ch.Problem(
        "feed", "Feed", "https://feeds.example/a.txt", "frozen", "2026-09-01", "12 entries"
    )
    body = ch.render([problem], DAY, "https://github.com/o/r/actions/runs/1")
    assert "| Feed<br>`feed` |" in body
    assert "frozen" in body
    assert "https://github.com/o/r/actions/runs/1" in body
    assert "2026-10-12" in body


def test_render_escapes_table_breaking_characters() -> None:
    problem = ch.Problem(
        "feed", "Feed", "https://feeds.example/a.txt", "dead", "2026-09-01", "bad | `x`\nnext"
    )
    row = next(line for line in ch.render([problem], DAY, "").splitlines() if "`feed`" in line)
    assert row.count(" | ") == 4  # five cells: the detail adds no extra column
    assert "\n" not in row
    assert "`x`" not in row


def test_one_source_crashing_does_not_stop_the_others() -> None:
    def fetch(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        if "feeds" in url:
            raise RuntimeError("boom")
        return FetchResult("ok", "45.9.21.0/24\n", content_type="text/plain")

    state, _, _ = ch.check([FEED, VENDOR], {}, fetch, DAY)
    assert state["feed"].failures == 1
    assert state["feed"].last_error == "RuntimeError: boom"
    assert state["vendor"].failures == 0


def test_the_report_does_not_promise_a_weekly_run() -> None:
    problem = ch.Problem("feed", "Feed", "https://feeds.example/a.txt", "dead", "2026-09-01", "x")
    assert "weekly" not in ch.render([problem], DAY, "").lower()


def test_the_error_detail_is_a_code_span() -> None:
    problem = ch.Problem(
        "feed", "Feed", "https://feeds.example/a.txt", "dead", "2026-09-01", "HTTP 410 from x"
    )
    assert "| `HTTP 410 from x` |" in ch.render([problem], DAY, "")


def test_a_rerun_after_a_frozen_failure_keeps_every_record_field() -> None:
    old = ch.Record(
        set_sha256="abc", valid=3, last_changed="2026-01-01", last_ok="2026-10-05", failures=0
    )
    new = ch._next(old, ch.FeedProbe(0, 0, "HTTP 503"), "2026-10-12")
    assert (new.set_sha256, new.valid, new.last_changed, new.last_ok) == (
        "abc",
        3,
        "2026-01-01",
        "2026-10-05",
    )


def test_sources_past_the_run_budget_keep_their_record_and_are_skipped() -> None:
    clock = iter([0.0, 1000.0])
    old = {"vendor": ch.Record(set_sha256="v", valid=1, last_changed="2026-10-01")}
    state, problems, skipped = ch.check(
        [FEED, VENDOR],
        old,
        _serve(feeds="45.9.20.1\n", vendor=FetchError("never fetched")),
        DAY,
        deadline=500.0,
        clock=lambda: next(clock),
    )
    assert skipped == ["vendor"]
    assert state["vendor"] == old["vendor"]
    assert state["feed"].valid == 1
    assert problems == []


def test_the_render_names_skipped_sources() -> None:
    body = ch.render([], DAY, "", skipped=["slow-feed"])
    assert "`slow-feed`" in body


def test_a_download_slower_than_the_source_limit_fails_that_source() -> None:
    ticks = iter(float(n) for n in range(0, 1000, 50))

    def trickle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=iter([b"45.9.20.1\n"] * 10))

    transport = ch.DeadlineTransport(httpx.MockTransport(trickle), 120, clock=lambda: next(ticks))
    with httpx.Client(transport=transport) as client:
        fetch = ch.HttpFetcher(client, retry_delays=(), spool=True)
        probe = ch.probe_feed(FEED, fetch)
    assert probe.error is not None
    assert "120" in probe.error


def test_a_download_within_the_source_limit_succeeds() -> None:
    def quick(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"45.9.20.1\n", headers={"Content-Type": "text/plain"})

    with httpx.Client(transport=ch.DeadlineTransport(httpx.MockTransport(quick), 120)) as client:
        probe = ch.probe_feed(FEED, ch.HttpFetcher(client, retry_delays=(), spool=True))
    assert (probe.valid, probe.problem) == (1, None)
