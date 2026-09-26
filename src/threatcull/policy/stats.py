# SPDX-License-Identifier: AGPL-3.0-only
"""Compile Stats: how much a Compile cleaned up, for the dashboard and its history.

Read from the TEMP ``scored`` table after ``mark_allowlisted`` has flagged it, so the
numbers describe exactly the Indicators this Compile scored.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from threatcull.outputs.stream import HOME_NETWORK
from threatcull.policy.scoring import tier_for
from threatcull.store.settings import Settings
from threatcull.store.sources import list_sources

TIERS = ("high", "medium", "low")
KINDS = ("ip", "domain")


@dataclass(frozen=True, slots=True)
class SourceShare:
    entries: int  # Indicators this Source lists in this Compile
    unique: int  # of those, how many no other Source lists


@dataclass(frozen=True, slots=True)
class CompileStats:
    listed: int  # entries across all fresh, enabled blocklist Sources
    unique: int  # distinct Indicators among them
    rejected: int  # lines the newest Fetch of each Source refused as invalid
    allowlisted: int
    home: int
    ranges: int = 0  # CIDR ranges left out of every Output
    tiers: dict[str, int] = field(default_factory=dict)
    sources: dict[str, SourceShare] = field(default_factory=dict)
    # Kept Indicators per kind and Tier, and per kind and category
    # (an Indicator in two categories counts in both). Empty for older Runs.
    kinds: dict[str, dict[str, int]] = field(default_factory=dict)
    categories: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def duplicates(self) -> int:
        return self.listed - self.unique

    @property
    def published(self) -> int:
        """Distinct Indicators left with a Tier after the Allowlist (own network included)."""
        return sum(self.tiers.values())

    def kept(self, kind: str) -> int:
        return sum(self.kinds.get(kind, {}).values())

    def to_json(self) -> dict[str, Any]:
        return {
            "listed": self.listed,
            "unique": self.unique,
            "rejected": self.rejected,
            "allowlisted": self.allowlisted,
            "home": self.home,
            "ranges": self.ranges,
            "tiers": dict(self.tiers),
            "sources": {sid: [s.entries, s.unique] for sid, s in self.sources.items()},
            "kinds": self.kinds,
            "categories": self.categories,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> CompileStats | None:
        """``None`` for a Run recorded before Compile Stats existed."""
        if "listed" not in data:
            return None
        return cls(
            listed=data["listed"],
            unique=data["unique"],
            rejected=data["rejected"],
            allowlisted=data["allowlisted"],
            home=data["home"],
            ranges=data.get("ranges", 0),
            tiers=dict(data["tiers"]),
            sources={sid: SourceShare(*pair) for sid, pair in data["sources"].items()},
            kinds={kind: dict(tiers) for kind, tiers in data.get("kinds", {}).items()},
            categories={kind: dict(c) for kind, c in data.get("categories", {}).items()},
        )


def compile_stats(conn: sqlite3.Connection, settings: Settings) -> CompileStats:
    listed = unique = allowlisted = home = ranges = 0
    tiers: Counter[str] = Counter(dict.fromkeys(TIERS, 0))
    kinds = {kind: Counter(dict.fromkeys(TIERS, 0)) for kind in KINDS}
    categories: dict[str, Counter[str]] = {kind: Counter() for kind in KINDS}
    entries: Counter[str] = Counter()
    only: Counter[str] = Counter()
    for row in conn.execute("SELECT kind, score, source_ids, categories, allowlisted FROM scored"):
        ids = row["source_ids"].split(",")
        unique += 1
        listed += len(ids)
        entries.update(ids)
        if len(ids) == 1:
            only[ids[0]] += 1
        if row["allowlisted"] == HOME_NETWORK:
            home += 1
        elif row["allowlisted"]:
            allowlisted += 1
        elif row["kind"] == "cidr":
            ranges += 1
        elif (tier := tier_for(row["score"], settings)) is not None:
            kind = row["kind"]
            tiers[tier] += 1
            kinds[kind][tier] += 1
            categories[kind].update(row["categories"].split(","))
    return CompileStats(
        listed=listed,
        unique=unique,
        rejected=_rejected(conn),
        allowlisted=allowlisted,
        home=home,
        ranges=ranges,
        tiers=dict(tiers),
        sources={sid: SourceShare(entries[sid], only[sid]) for sid in sorted(entries)},
        kinds={kind: dict(counts) for kind, counts in kinds.items()},
        categories={kind: dict(counts) for kind, counts in categories.items()},
    )


def _rejected(conn: sqlite3.Connection) -> int:
    """Invalid lines in the newest Fetch (that counted lines) of each enabled blocklist."""
    enabled = {s.id for s in list_sources(conn, enabled_only=True, role="blocklist")}
    newest: dict[str, int] = {}
    rows = conn.execute(
        "SELECT source_id, counts FROM runs WHERE type = 'fetch' AND status = 'ok' "
        "ORDER BY started_at DESC, id DESC"
    )
    for row in rows:
        source_id = row["source_id"]
        if source_id in enabled and source_id not in newest:
            counts = json.loads(row["counts"])
            if "invalid" in counts:
                newest[source_id] = counts["invalid"]
    return sum(newest.values())
