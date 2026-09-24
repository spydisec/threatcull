# SPDX-License-Identifier: AGPL-3.0-only
"""Render an Output in one Format, headed by attribution for every contributing Source."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from threatcull.policy.scoring import ScoredIndicator
from threatcull.store.outputs import OutputFormat

_COMMENT = {"plain": "#", "hosts": "#", "adguard": "!", "rpz": ";"}


@dataclass(frozen=True, slots=True)
class Attribution:
    name: str
    licence: str
    licence_url: str


@dataclass(frozen=True, slots=True)
class RenderContext:
    output_name: str
    generated_at: str
    attributions: tuple[Attribution, ...]
    source_names: Mapping[str, str]


def render(fmt: OutputFormat, items: Sequence[ScoredIndicator], ctx: RenderContext) -> str:
    if fmt == "csv":
        return _csv(items, ctx)
    if fmt == "json":
        return _json(items, ctx)
    prefix = _COMMENT[fmt]
    lines = [f"{prefix} {line}" for line in _header(ctx, len(items))]
    if fmt == "plain":
        lines += [item.value for item in items]
    elif fmt == "hosts":
        # 0.0.0.0 here is the hosts-file sink address (routes nowhere), not a bind address.
        lines += [f"0.0.0.0 {item.value}" for item in items]
    elif fmt == "adguard":
        lines += [f"||{item.value}^" for item in items]
    else:
        serial = int(datetime.fromisoformat(ctx.generated_at).timestamp())
        lines += [
            "$TTL 300",
            f"@ IN SOA localhost. hostmaster.localhost. {serial} 3600 600 86400 300",
            "@ IN NS localhost.",
        ]
        for item in items:
            lines += [f"{item.value} CNAME .", f"*.{item.value} CNAME ."]
    return "\n".join(lines) + "\n"


def _header(ctx: RenderContext, count: int) -> list[str]:
    return [
        f"ThreatCull output: {ctx.output_name}",
        f"Generated: {ctx.generated_at}",
        f"Entries: {count}",
        "Sources (each under its own terms):",
        *(f"  - {a.name} | {a.licence} | {a.licence_url}" for a in ctx.attributions),
    ]


def _names(item: ScoredIndicator, ctx: RenderContext) -> list[str]:
    return [ctx.source_names.get(source_id, source_id) for source_id in item.source_ids]


def _csv(items: Sequence[ScoredIndicator], ctx: RenderContext) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["indicator", "kind", "score", "tier", "sources", "first_seen", "last_seen"])
    for item in items:
        writer.writerow(
            [
                item.value,
                item.kind,
                item.score,
                item.tier,
                ";".join(_names(item, ctx)),
                item.first_seen,
                item.last_seen,
            ]
        )
    return buffer.getvalue()


def _json(items: Sequence[ScoredIndicator], ctx: RenderContext) -> str:
    document = {
        "output": ctx.output_name,
        "generated_at": ctx.generated_at,
        "count": len(items),
        "attribution": [
            {"name": a.name, "licence": a.licence, "licence_url": a.licence_url}
            for a in ctx.attributions
        ],
        "indicators": [
            {
                "indicator": item.value,
                "kind": item.kind,
                "score": item.score,
                "tier": item.tier,
                "sources": _names(item, ctx),
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
            }
            for item in items
        ],
    }
    return json.dumps(document, indent=2) + "\n"
