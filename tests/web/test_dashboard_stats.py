# SPDX-License-Identifier: AGPL-3.0-only
"""The dashboard's cleanup funnel, Tier split, Source overlap and Compile trend."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_compiling import _setup
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.indicators import Indicator
from threatcull.policy.stats import CompileStats, SourceShare
from threatcull.store.outputs import OutputSpec
from threatcull.store.runs import Run, compile_history
from threatcull.store.sightings import record_fetch_success
from threatcull.web.dashboard import (
    FUNNEL_WIDTH,
    Health,
    OutputChange,
    chart_data,
    funnel,
    health,
    output_changes,
    source_rows,
)
from threatcull.web.deps import open_db

STATS = CompileStats(
    listed=900,
    unique=600,
    rejected=100,
    allowlisted=40,
    home=10,
    tiers={"high": 50, "medium": 150, "low": 350},
    sources={"a": SourceShare(700, 400), "b": SourceShare(200, 0)},
)


def _run(stamp: str, stats: CompileStats) -> Run:
    return Run(1, "compile", None, stamp, stamp, "ok", {}, None, (), stats.to_json())


def test_funnel_scales_every_step_against_what_was_received() -> None:
    steps = funnel(STATS)
    assert [(s.label, s.value) for s in steps] == [
        ("Received from Sources", 1000),
        ("Rejected as invalid", 100),
        ("Duplicates merged", 300),
        ("Allowlisted", 40),
        ("Home Network", 10),
        ("Unique Indicators kept", 550),
    ]
    assert steps[0].width == FUNNEL_WIDTH
    assert steps[2].width == FUNNEL_WIDTH * 0.3
    assert steps[2].note == "30.0% of received"


def test_source_rows_are_largest_first_with_their_unique_share() -> None:
    rows = source_rows(STATS, {"a": "Source A"})
    assert [(r.name, r.entries, r.unique) for r in rows] == [("Source A", 700, 400), ("b", 200, 0)]
    assert rows[0].width == 100
    assert rows[0].unique_share == 400 / 700


def test_chart_data_splits_kinds_and_buckets_the_trends() -> None:
    stats = CompileStats(
        listed=10,
        unique=10,
        rejected=0,
        allowlisted=0,
        home=0,
        tiers={"high": 1, "medium": 2, "low": 7},
        kinds={
            "ip": {"high": 1, "medium": 2, "low": 3},
            "domain": {"high": 0, "medium": 0, "low": 4},
        },
        categories={"ip": {"malicious": 6}, "domain": {"phishing": 3, "spam": 1}},
    )
    now = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    history = [
        _run("2026-09-20T10:00:00+00:00", stats),
        _run("2026-09-25T09:00:00+00:00", stats),
        _run("2026-09-25T11:00:00+00:00", stats),
    ]
    data = chart_data(stats, history, now=now)
    assert data["tiers"]["values"] == [1, 2, 3]
    assert data["tiers"]["kind"] == "IPs"
    assert data["categories"]["keys"] == ["phishing", "spam"]
    assert data["categories"]["labels"] == ["Phishing", "Spam / scam"]
    assert data["categories"]["values"] == [3, 1]
    assert data["day"]["labels"] == ["09:00", "11:00"]
    assert data["day"]["ip"] == [6, 6]
    assert data["day"]["delta"] == {"ip": 0, "high": 0}
    assert data["month"]["labels"] == ["Sep 20", "Sep 25"]


def test_health_reports_the_worst_problem_first() -> None:
    ok = _run("2026-09-25T09:00:00+00:00", STATS)
    assert health(None, [], 0).label == "No Compile yet"
    assert health(ok, [], 0) == Health("ok", "Pipeline healthy")
    assert health(ok, [], 2).tone == "warn"
    blocked = Run(2, "compile", None, "t", "t", "blocked", {}, None)
    assert health(blocked, [], 0).label == "Compile blocked by the Shrink Guard"


def test_output_changes_compare_the_last_two_compiles() -> None:
    spec_a = OutputSpec("a", "ip", frozenset({"malicious"}), "low", None, "plain", last_count=5)
    spec_b = OutputSpec("b", "ip", frozenset({"malicious"}), "low", None, "plain")
    compiles = [
        Run(1, "compile", None, "t1", "t1", "ok", {"a": 4}, None),
        Run(2, "compile", None, "t2", "t2", "ok", {"a": 7, "b": 1}, None),
    ]
    assert output_changes([spec_a, spec_b], compiles) == [
        OutputChange("a", 7, 3),
        OutputChange("b", 1, None),
    ]


def test_dashboard_shows_the_cleanup_funnel_after_a_compile(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert "No Compile has recorded cleanup numbers yet" in client.get("/").text
    conn = open_db(tmp_path)
    try:
        _setup(conn, utcnow())
        compile_outputs(conn, tmp_path / "outputs", now=utcnow() - timedelta(minutes=5))
        compile_outputs(conn, tmp_path / "outputs", now=utcnow())
        assert len(compile_history(conn)) == 2
    finally:
        conn.close()
    page = client.get("/").text
    assert "Duplicates merged" in page
    assert "Unique Indicators kept" in page
    assert "Source A" in page
    assert 'data-chart="tiers"' in page
    assert 'id="chart-data"' in page


def test_dashboard_fragment_is_only_the_dashboard_body(client: TestClient, logged_in: str) -> None:
    response = client.get("/partials/dashboard")
    assert response.status_code == 200
    assert "<html" not in response.text
    assert 'id="dashboard-body"' in response.text
    assert 'hx-trigger="every 60s"' in response.text


def test_a_blocked_compile_explains_itself_and_links_to_force_compile(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    conn = open_db(tmp_path)
    try:
        now = utcnow()
        _setup(conn, now)
        compile_outputs(conn, tmp_path / "outputs", now=now)
        later = now + timedelta(minutes=1)
        record_fetch_success(
            conn, "a", {Indicator("45.9.20.1", "ip")}, now=later, etag=None, last_modified=None
        )
        assert compile_outputs(conn, tmp_path / "outputs", now=later).status == "blocked"
    finally:
        conn.close()
    page = client.get("/").text
    assert "Outputs not updated" in page
    assert "/runs#force-compile" in page
    assert 'id="force-compile" open' in client.get("/runs").text
