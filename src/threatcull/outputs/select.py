# SPDX-License-Identifier: AGPL-3.0-only
"""Pick the Indicators an Output publishes, strongest first."""

from __future__ import annotations

from collections.abc import Sequence

from threatcull.policy.scoring import TIER_RANK, ScoredIndicator
from threatcull.store.outputs import OutputSpec


def select(scored: Sequence[ScoredIndicator], spec: OutputSpec) -> list[ScoredIndicator]:
    kinds = {"ip", "cidr"} if spec.kind == "ip" else {"domain"}
    floor = TIER_RANK[spec.min_tier]
    chosen = [
        item
        for item in scored
        if item.kind in kinds
        and TIER_RANK[item.tier] >= floor
        and item.categories & spec.categories
    ]
    chosen.sort(key=lambda item: item.value)
    chosen.sort(key=lambda item: (item.score, item.last_seen), reverse=True)
    return chosen[: spec.max_entries] if spec.max_entries else chosen
