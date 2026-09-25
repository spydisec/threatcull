# SPDX-License-Identifier: AGPL-3.0-only
"""The dashboard's cleanup funnel, Tier split, Source overlap and Compile trend."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_compiling import _setup
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.policy.stats import CompileStats, SourceShare
from threatcull.store.runs import Run, compile_history
from threatcull.web.dashboard import FUNNEL_WIDTH, funnel, source_rows, tier_bar, trend
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


def test_tier_bar_segments_fill_the_width_in_tier_order() -> None:
    segments = tier_bar(STATS)
    assert [s.tier for s in segments] == ["high", "medium", "low"]
    assert segments[1].x == segments[0].width
    assert round(sum(s.width for s in segments)) == FUNNEL_WIDTH


def test_source_rows_are_largest_first_with_their_unique_share() -> None:
    rows = source_rows(STATS, {"a": "Source A"})
    assert [(r.name, r.entries, r.unique) for r in rows] == [("Source A", 700, 400), ("b", 200, 0)]
    assert rows[0].width == 100
    assert rows[0].unique_share == 400 / 700


def test_trend_needs_two_compiles_and_labels_each_point() -> None:
    assert trend([_run("2026-09-24T10:00:00+00:00", STATS)]) is None
    chart = trend(
        [_run("2026-09-24T10:00:00+00:00", STATS), _run("2026-09-25T10:00:00+00:00", STATS)]
    )
    assert chart is not None
    assert chart.series[0].name == "Unique Indicators kept"
    assert chart.series[0].dots[1].title.startswith("Unique Indicators kept: 550 (Sep 25")
    assert chart.y_ticks[-1][1] == "550"


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
    assert "<polyline" in page


def test_stats_fragment_is_only_the_cleanup_section(client: TestClient, logged_in: str) -> None:
    response = client.get("/partials/stats")
    assert response.status_code == 200
    assert "<html" not in response.text
    assert 'id="cleanup"' in response.text
