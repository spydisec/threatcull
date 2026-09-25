# SPDX-License-Identifier: AGPL-3.0-only
"""Dashboard view-models: the cleanup funnel, the Compile trend and Source overlap.

Charts are server-rendered SVG. The CSP forbids inline styles, but SVG geometry
attributes are fine, so this module computes every coordinate and the template
only places them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from threatcull.policy.stats import TIERS, CompileStats
from threatcull.store.runs import Run

FUNNEL_WIDTH = 1000


@dataclass(frozen=True, slots=True)
class FunnelStep:
    label: str
    value: int
    width: float  # bar length in FUNNEL_WIDTH units
    tone: str  # "in", "out" (removed by this step) or "keep"
    note: str


def funnel(stats: CompileStats) -> list[FunnelStep]:
    received = stats.listed + stats.rejected
    scale = FUNNEL_WIDTH / received if received else 0.0

    def step(label: str, value: int, tone: str, note: str) -> FunnelStep:
        return FunnelStep(label, value, max(value * scale, 2.0 if value else 0.0), tone, note)

    def share(value: int) -> str:
        return f"{value / received:.1%} of received" if received else ""

    return [
        step("Received from Sources", received, "in", "newest Fetch of each Source"),
        step("Rejected as invalid", stats.rejected, "out", share(stats.rejected)),
        step("Duplicates merged", stats.duplicates, "out", share(stats.duplicates)),
        step("Allowlisted", stats.allowlisted, "out", share(stats.allowlisted)),
        step("Home Network", stats.home, "out", share(stats.home)),
        step("Unique Indicators kept", stats.published, "keep", share(stats.published)),
    ]


@dataclass(frozen=True, slots=True)
class TierSegment:
    tier: str
    value: int
    x: float
    width: float


def tier_bar(stats: CompileStats) -> list[TierSegment]:
    total = stats.published
    segments: list[TierSegment] = []
    x = 0.0
    for tier in TIERS:
        value = stats.tiers.get(tier, 0)
        width = FUNNEL_WIDTH * value / total if total else 0.0
        segments.append(TierSegment(tier, value, x, width))
        x += width
    return segments


@dataclass(frozen=True, slots=True)
class SourceRow:
    name: str
    entries: int
    unique: int
    unique_share: float  # 0..1
    width: float  # entries bar, in 0..100 of the largest Source
    unique_width: float


def source_rows(stats: CompileStats, names: Mapping[str, str]) -> list[SourceRow]:
    largest = max((share.entries for share in stats.sources.values()), default=0)
    rows = [
        SourceRow(
            name=names.get(source_id, source_id),
            entries=share.entries,
            unique=share.unique,
            unique_share=share.unique / share.entries if share.entries else 0.0,
            width=100 * share.entries / largest if largest else 0.0,
            unique_width=100 * share.unique / largest if largest else 0.0,
        )
        for source_id, share in stats.sources.items()
    ]
    return sorted(rows, key=lambda row: row.entries, reverse=True)


# ---- Trend chart ---------------------------------------------------------------

CHART_W, CHART_H = 640, 200
PAD_L, PAD_R, PAD_T, PAD_B = 56, 12, 12, 24
MIN_TREND_POINTS = 2


@dataclass(frozen=True, slots=True)
class Dot:
    x: float
    y: float
    title: str


@dataclass(frozen=True, slots=True)
class Series:
    name: str
    tone: str
    points: str  # SVG polyline points
    dots: tuple[Dot, ...]


@dataclass(frozen=True, slots=True)
class Trend:
    series: tuple[Series, ...]
    y_ticks: tuple[tuple[float, str], ...]  # (y, label)
    first_label: str
    last_label: str
    width: int = CHART_W
    height: int = CHART_H


def _compact(value: float) -> str:
    for size, suffix in ((1_000_000, "M"), (1_000, "k")):
        if value >= size:
            return f"{value / size:.1f}".rstrip("0").rstrip(".") + suffix
    return f"{value:.0f}"


def _day(stamp: str) -> str:
    return datetime.fromisoformat(stamp).strftime("%b %d %H:%M")


def trend(runs: Sequence[Run]) -> Trend | None:
    """Kept, duplicates and removed per Compile, oldest first; None below two points."""
    points = [(run, stats) for run in runs if (stats := CompileStats.from_json(run.stats))]
    if len(points) < MIN_TREND_POINTS:
        return None
    lines = (
        ("Unique Indicators kept", "keep", [s.published for _, s in points]),
        ("Duplicates merged", "dup", [s.duplicates for _, s in points]),
        (
            "Rejected, allowlisted or Home Network",
            "out",
            [s.rejected + s.allowlisted + s.home for _, s in points],
        ),
    )
    top = max(max(values) for _, _, values in lines) or 1
    inner_w, inner_h = CHART_W - PAD_L - PAD_R, CHART_H - PAD_T - PAD_B
    step = inner_w / (len(points) - 1)

    def xy(index: int, value: int) -> tuple[float, float]:
        return round(PAD_L + index * step, 1), round(PAD_T + inner_h * (1 - value / top), 1)

    series = []
    for name, tone, values in lines:
        coords = [xy(i, v) for i, v in enumerate(values)]
        dots = tuple(
            Dot(x, y, f"{name}: {values[i]:,} ({_day(points[i][0].started_at)} UTC)")
            for i, (x, y) in enumerate(coords)
        )
        series.append(Series(name, tone, " ".join(f"{x},{y}" for x, y in coords), dots))
    ticks = tuple((round(PAD_T + inner_h * (1 - f), 1), _compact(top * f)) for f in (0.0, 0.5, 1.0))
    return Trend(
        tuple(series),
        ticks,
        _day(points[0][0].started_at),
        _day(points[-1][0].started_at),
    )
