# SPDX-License-Identifier: AGPL-3.0-only
"""Dashboard view-models: pipeline health, chart data, latest changes, the cleanup
funnel and Source overlap.

The funnel and overlap bars are server-rendered SVG (the CSP forbids inline styles,
but SVG geometry attributes are fine). The Tier, category and trend charts are drawn
by the Chart.js island from the JSON ``chart_data`` builds.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from threatcull.policy.stats import TIERS, CompileStats
from threatcull.store.outputs import OutputSpec
from threatcull.store.runs import Run
from threatcull.store.sources import Source

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
        step("My network", stats.home, "out", share(stats.home)),
        step("Ranges left out", stats.ranges, "out", share(stats.ranges)),
        step("Unique Indicators kept", stats.published, "keep", share(stats.published)),
    ]


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


# ---- Pipeline health -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Health:
    tone: str  # "ok", "warn", "bad" or "off"
    label: str


def health(last_compile: Run | None, blocklists: Sequence[Source], stale: int) -> Health:
    failing = sum(1 for source in blocklists if source.last_error)
    if last_compile is None:
        return Health("off", "No Compile yet")
    if last_compile.status == "failed":
        return Health("bad", "Last Compile failed")
    if last_compile.status == "blocked":
        return Health("warn", "Compile blocked by the Shrink Guard")
    if failing or stale:
        problems = [f"{failing} failing" if failing else "", f"{stale} Stale" if stale else ""]
        return Health("warn", "Sources need attention: " + ", ".join(p for p in problems if p))
    if last_compile.status == "running":
        return Health("warn", "Compile running")
    return Health("ok", "Pipeline healthy")


# ---- Latest changes --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceChange:
    name: str
    status: str
    added: int
    removed: int
    at: str | None


def source_changes(fetches: Sequence[Run], names: Mapping[str, str]) -> list[SourceChange]:
    """The newest Fetch of each Source in ``names`` (``fetches`` newest first)."""
    newest: dict[str, SourceChange] = {}
    for run in fetches:
        source_id = run.source_id
        if source_id is not None and source_id in names and source_id not in newest:
            newest[source_id] = SourceChange(
                names[source_id],
                run.status,
                run.counts.get("added", 0),
                run.counts.get("removed", 0),
                run.finished_at,
            )
    return sorted(newest.values(), key=lambda c: (-(c.added + c.removed), c.name))


@dataclass(frozen=True, slots=True)
class OutputChange:
    name: str
    count: int | None
    change: int | None  # since the previous finished Compile


def output_changes(outputs: Sequence[OutputSpec], compiles: Sequence[Run]) -> list[OutputChange]:
    """``compiles``: finished Compiles, oldest first."""
    now = compiles[-1].counts if compiles else {}
    before = compiles[-2].counts if len(compiles) > 1 else {}
    rows = []
    for spec in outputs:
        count = now.get(spec.name, spec.last_count)
        previous = before.get(spec.name)
        change = count - previous if count is not None and previous is not None else None
        rows.append(OutputChange(spec.name, count, change))
    return rows


# ---- Chart data (drawn by the Chart.js island) -------------------------------------


CATEGORY_LABELS = {
    "malicious": "Malicious",
    "c2": "C2",
    "scanner": "Scanners",
    "phishing": "Phishing",
    "spam": "Spam / scam",
    "ads_tracking": "Ads / tracking",
    "infrastructure": "Infrastructure",
}


def _delta(values: Sequence[int | None]) -> int | None:
    known = [value for value in values if value is not None]
    return known[-1] - known[0] if len(known) > 1 else None


def _series(points: Sequence[tuple[Run, CompileStats]], label: str) -> dict[str, Any]:
    def kept(stats: CompileStats, kind: str) -> int | None:
        return stats.kept(kind) if stats.kinds else None

    ip = [kept(stats, "ip") for _, stats in points]
    high = [stats.tiers.get("high", 0) for _, stats in points]
    return {
        "labels": [label_for(run.started_at, label) for run, _ in points],
        "ip": ip,
        "domain": [kept(stats, "domain") for _, stats in points],
        "high": high,
        "delta": {"ip": _delta(ip), "high": _delta(high)},
    }


def label_for(stamp: str, style: str) -> str:
    moment = datetime.fromisoformat(stamp)
    return moment.strftime("%H:%M") if style == "time" else moment.strftime("%b %d")


def chart_data(stats: CompileStats, history: Sequence[Run], *, now: datetime) -> dict[str, Any]:
    """``history``: finished Compiles with stats, oldest first, covering 30 days."""
    points = [(run, s) for run in history if (s := CompileStats.from_json(run.stats))]
    day_start = (now - timedelta(hours=24)).isoformat()
    last_24h = [(run, s) for run, s in points if run.started_at >= day_start]
    by_day: dict[str, tuple[Run, CompileStats]] = {}
    for run, s in points:
        by_day[run.started_at[:10]] = (run, s)  # the day's last Compile wins
    domain_categories = stats.categories.get("domain", {})
    categories = domain_categories or stats.categories.get("ip", {})
    ordered = sorted(categories.items(), key=lambda item: -item[1])
    ip_tiers = [stats.kinds.get("ip", {}).get(t, 0) for t in TIERS]
    domain_tiers = [stats.kinds.get("domain", {}).get(t, 0) for t in TIERS]
    tier_kind = "IPs" if any(ip_tiers) or not any(domain_tiers) else "domains"
    tier_values = ip_tiers if tier_kind == "IPs" else domain_tiers
    return {
        "tiers": {
            "labels": list(TIERS),
            "ip": ip_tiers,
            "domain": domain_tiers,
            "kind": tier_kind,
            "values": tier_values,
            "total": sum(tier_values),
        },
        "categories": {
            "title": "Domain categories" if domain_categories else "IP categories",
            "keys": [name for name, _ in ordered],
            "labels": [CATEGORY_LABELS.get(name, name) for name, _ in ordered],
            "values": [value for _, value in ordered],
        },
        "day": _series(last_24h, "time"),
        "month": _series(list(by_day.values()), "date"),
    }
