# SPDX-License-Identifier: AGPL-3.0-only
"""Confidence Score (distinct Source Families agreeing) and Tiers."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from threatcull.clock import ts
from threatcull.indicators import IndicatorKind
from threatcull.store.settings import Settings

Tier = Literal["high", "medium", "low"]
TIER_RANK: dict[Tier, int] = {"low": 1, "medium": 2, "high": 3}

_SCORED_ALL = """
    SELECT i.value, i.kind, COUNT(DISTINCT src.family) AS score,
        GROUP_CONCAT(src.id) AS source_ids, GROUP_CONCAT(DISTINCT src.category) AS categories,
        MIN(sg.first_seen) AS first_seen, MAX(sg.last_seen) AS last_seen
    FROM sightings sg
    JOIN sources src ON src.id = sg.source_id
    JOIN indicators i ON i.id = sg.indicator_id
    WHERE src.enabled = 1 AND src.role = 'blocklist' AND sg.current = 1
        AND sg.last_seen >= :window_start AND src.last_success_at >= :stale_cutoff
    GROUP BY i.id
"""

_SCORED_ONE = """
    SELECT i.value, i.kind, COUNT(DISTINCT src.family) AS score,
        GROUP_CONCAT(src.id) AS source_ids, GROUP_CONCAT(DISTINCT src.category) AS categories,
        MIN(sg.first_seen) AS first_seen, MAX(sg.last_seen) AS last_seen
    FROM indicators i
    JOIN sightings sg ON sg.indicator_id = i.id
    JOIN sources src ON src.id = sg.source_id
    WHERE i.value = :value AND src.enabled = 1 AND src.role = 'blocklist' AND sg.current = 1
        AND sg.last_seen >= :window_start AND src.last_success_at >= :stale_cutoff
    GROUP BY i.id
"""


@dataclass(frozen=True, slots=True)
class ScoredIndicator:
    value: str
    kind: IndicatorKind
    score: int
    tier: Tier
    source_ids: tuple[str, ...]
    categories: frozenset[str]
    first_seen: str
    last_seen: str


def tier_for(score: int, settings: Settings) -> Tier | None:
    if score >= settings.tier_high:
        return "high"
    if score >= settings.tier_medium:
        return "medium"
    if score >= 1:
        return "low"
    return None


def scored_indicators(
    conn: sqlite3.Connection, *, now: datetime, settings: Settings, value: str | None = None
) -> list[ScoredIndicator]:
    """Score every Indicator with a current, in-window Sighting from an enabled, fresh Source."""
    params = {
        "window_start": ts(now - timedelta(days=settings.active_window_days)),
        "stale_cutoff": ts(now - timedelta(hours=settings.stale_after_hours)),
        "value": value,
    }
    rows = conn.execute(_SCORED_ALL if value is None else _SCORED_ONE, params)
    scored: list[ScoredIndicator] = []
    for row in rows:
        tier = tier_for(row["score"], settings)
        if tier is None:
            continue
        scored.append(
            ScoredIndicator(
                value=row["value"],
                kind=row["kind"],
                score=row["score"],
                tier=tier,
                source_ids=tuple(sorted(row["source_ids"].split(","))),
                categories=frozenset(row["categories"].split(",")),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )
        )
    return scored
