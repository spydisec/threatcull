# SPDX-License-Identifier: AGPL-3.0-only
"""'Why is this listed?' — explain one Indicator."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from threatcull.indicators import IndicatorKind, normalize
from threatcull.outputs.select import select
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import Tier, scored_indicators
from threatcull.store.allowlist import AllowlistEntry, builtin_entries, operator_entries
from threatcull.store.outputs import list_outputs
from threatcull.store.settings import load_settings


@dataclass(frozen=True, slots=True)
class SightingView:
    source_id: str
    source_name: str
    enabled: bool
    current: bool
    first_seen: str
    last_seen: str


@dataclass(frozen=True, slots=True)
class LookupResult:
    value: str
    kind: IndicatorKind
    sightings: tuple[SightingView, ...]
    score: int
    tier: Tier | None
    allowlisted_by: AllowlistEntry | None
    eligible_outputs: tuple[str, ...]


def lookup(conn: sqlite3.Connection, raw: str, *, now: datetime) -> LookupResult | None:
    """Explain one IP, CIDR or domain.

    ``eligible_outputs`` means the Indicator qualifies by kind, Tier and category; an
    Output with ``max_entries`` may still cut it during Compile.
    """
    indicator = normalize(raw, "ip") or normalize(raw, "domain")
    if indicator is None:
        return None
    rows = conn.execute(
        """
        SELECT s.id, s.name, s.enabled, sg.current, sg.first_seen, sg.last_seen
        FROM indicators i
        JOIN sightings sg ON sg.indicator_id = i.id
        JOIN sources s ON s.id = sg.source_id
        WHERE i.value = ? ORDER BY s.name
        """,
        (indicator.value,),
    )
    sightings = tuple(
        SightingView(
            r["id"],
            r["name"],
            bool(r["enabled"]),
            bool(r["current"]),
            r["first_seen"],
            r["last_seen"],
        )
        for r in rows
    )
    matches = scored_indicators(conn, now=now, settings=load_settings(conn), value=indicator.value)
    scored = matches[0] if matches else None
    allowlisted_by = Allowlist([*operator_entries(conn), *builtin_entries(conn)]).match(
        indicator.value, indicator.kind
    )
    eligible: tuple[str, ...] = ()
    if scored is not None and allowlisted_by is None:
        eligible = tuple(spec.name for spec in list_outputs(conn) if select([scored], spec))
    return LookupResult(
        value=indicator.value,
        kind=indicator.kind,
        sightings=sightings,
        score=scored.score if scored else 0,
        tier=scored.tier if scored else None,
        allowlisted_by=allowlisted_by,
        eligible_outputs=eligible,
    )


def output_labels(conn: sqlite3.Connection, names: tuple[str, ...]) -> tuple[str, ...]:
    """Eligible Output names, each with its ``max_entries`` cap when it has one.

    Qualifying by kind/Tier/category doesn't guarantee publication: an Output
    with a cap may still cut the Indicator during Compile, so show the cap.
    """
    caps = {spec.name: spec.max_entries for spec in list_outputs(conn)}
    return tuple(f"{name} (cap {caps[name]})" if caps.get(name) else name for name in names)
