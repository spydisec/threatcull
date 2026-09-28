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
    url: str  # the feed URL, or "local file" for a file:// Source


@dataclass(frozen=True, slots=True)
class RenderContext:
    output_name: str
    generated_at: str
    attributions: tuple[Attribution, ...]
    source_names: Mapping[str, str]


def render(fmt: OutputFormat, items: Sequence[ScoredIndicator], ctx: RenderContext) -> str:
    """Render a whole Output in memory; Compile streams the same pieces to a file."""
    body = "".join(entry(fmt, item, ctx, index) for index, item in enumerate(items))
    return head(fmt, ctx, len(items)) + body + tail(fmt, len(items))


def head(fmt: OutputFormat, ctx: RenderContext, count: int) -> str:
    """Everything before the first entry; needs the final count and attributions."""
    if fmt == "csv":
        return _csv_row(
            ["indicator", "kind", "score", "tier", "sources", "first_seen", "last_seen"]
        )
    if fmt == "json":
        document = {
            "output": ctx.output_name,
            "generated_at": ctx.generated_at,
            "count": count,
            "attribution": [{"name": a.name, "url": a.url} for a in ctx.attributions],
        }
        # Reopen the object after "attribution" so the indicators array can be streamed.
        return json.dumps(document, indent=2).removesuffix("\n}") + ',\n  "indicators": ['
    prefix = _COMMENT[fmt]
    lines = [f"{prefix} {line}" for line in _header(ctx, count)]
    if fmt == "rpz":
        serial = int(datetime.fromisoformat(ctx.generated_at).timestamp())
        lines += [
            "$TTL 300",
            f"@ IN SOA localhost. hostmaster.localhost. {serial} 3600 600 86400 300",
            "@ IN NS localhost.",
        ]
    return "".join(f"{line}\n" for line in lines)


def entry(fmt: OutputFormat, item: ScoredIndicator, ctx: RenderContext, index: int) -> str:
    """One Indicator's text; ``index`` is its 0-based position in the Output."""
    if "\n" in item.value or "\r" in item.value:
        # normalize() refuses these; never let one become extra rules in a feed.
        raise ValueError(f"refusing to publish a value with a line break: {item.value!r}")
    if fmt == "plain":
        return f"{item.value}\n"
    if fmt == "hosts":
        # 0.0.0.0 here is the hosts-file sink address (routes nowhere), not a bind address.
        return f"0.0.0.0 {item.value}\n"
    if fmt == "adguard":
        return f"||{item.value}^\n"
    if fmt == "rpz":
        return f"{item.value} CNAME .\n*.{item.value} CNAME .\n"
    names = [ctx.source_names.get(source_id, source_id) for source_id in item.source_ids]
    if fmt == "csv":
        return _csv_row(
            [
                item.value,
                item.kind,
                item.score,
                item.tier,
                ";".join(names),
                item.first_seen,
                item.last_seen,
            ]
        )
    record = {
        "indicator": item.value,
        "kind": item.kind,
        "score": item.score,
        "tier": item.tier,
        "sources": names,
        "first_seen": item.first_seen,
        "last_seen": item.last_seen,
    }
    text = json.dumps(record, indent=2).replace("\n", "\n    ")
    return f"{',' if index else ''}\n    {text}"


def tail(fmt: OutputFormat, count: int) -> str:
    """Everything after the last entry."""
    if fmt != "json":
        return ""
    return "\n  ]\n}\n" if count else "]\n}\n"


def _header(ctx: RenderContext, count: int) -> list[str]:
    return [
        f"ThreatCull output: {ctx.output_name}",
        f"Generated: {ctx.generated_at}",
        f"Entries: {count}",
        "Sources:",
        *(f"  - {a.name} | {a.url}" for a in ctx.attributions),
    ]


def _csv_row(row: Sequence[object]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(row)
    return buffer.getvalue()
