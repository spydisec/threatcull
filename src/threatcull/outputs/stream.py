# SPDX-License-Identifier: AGPL-3.0-only
"""Streamed selection and rendering: write each Output from the ``scored`` table to a file."""

from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from threatcull.indicators import IndicatorKind
from threatcull.outputs.files import output_path
from threatcull.outputs.render import Attribution, RenderContext, entry, head, tail
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import ScoredIndicator, min_score, to_scored
from threatcull.store.outputs import OutputSpec
from threatcull.store.settings import Settings
from threatcull.store.sources import Source

# Same order as ``select()``: strongest first, then most recently seen, then by value.
_SELECT = """
    SELECT value, kind, score, source_ids, categories, first_seen, last_seen FROM scored
    WHERE allowlisted = 0 AND score >= :min_score
        AND kind IN (SELECT value FROM json_each(:kinds))
        AND EXISTS (
            SELECT 1 FROM json_each(:categories) AS wanted
            WHERE instr(',' || scored.categories || ',', ',' || wanted.value || ',') > 0
        )
    ORDER BY score DESC, last_seen DESC, value ASC
    LIMIT :limit
"""


@dataclass(frozen=True, slots=True)
class StagedOutput:
    """An Output rendered to ``tmp``, waiting to replace ``path``."""

    name: str
    path: Path
    tmp: Path
    count: int


def mark_allowlisted(conn: sqlite3.Connection, allowlist: Allowlist) -> int:
    """Flag every ``scored`` row the Allowlist excludes; returns how many were flagged."""

    def excluded(value: str, kind: str) -> bool:
        return allowlist.match(value, cast(IndicatorKind, kind)) is not None

    conn.create_function("threatcull_allowlisted", 2, excluded, deterministic=True)
    try:
        return conn.execute(
            "UPDATE scored SET allowlisted = 1 WHERE threatcull_allowlisted(value, kind)"
        ).rowcount
    finally:
        conn.create_function("threatcull_allowlisted", 2, None)


def stage_output(
    conn: sqlite3.Connection,
    spec: OutputSpec,
    out_dir: Path,
    *,
    generated_at: str,
    sources: Mapping[str, Source],
    settings: Settings,
) -> StagedOutput:
    """Render ``spec`` to a temp file next to its final path, one Indicator at a time."""
    path = output_path(out_dir, spec)
    body = path.with_name(f".{path.name}.body.tmp")
    tmp = path.with_name(f".{path.name}.tmp")
    names = {source_id: source.name for source_id, source in sources.items()}
    ctx = RenderContext(spec.name, generated_at, (), names)
    contributing: set[str] = set()
    count = 0
    try:
        with body.open("w", encoding="utf-8") as out:
            for item in _selected(conn, spec, settings):
                out.write(entry(spec.format, item, ctx, count))
                contributing.update(item.source_ids)
                count += 1
        ctx = RenderContext(spec.name, generated_at, _attributions(contributing, sources), names)
        with tmp.open("wb") as out, body.open("rb") as rendered:
            out.write(head(spec.format, ctx, count).encode("utf-8"))
            shutil.copyfileobj(rendered, out)
            out.write(tail(spec.format, count).encode("utf-8"))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        body.unlink(missing_ok=True)
    return StagedOutput(spec.name, path, tmp, count)


def _selected(
    conn: sqlite3.Connection, spec: OutputSpec, settings: Settings
) -> Iterator[ScoredIndicator]:
    params = {
        "min_score": min_score(spec.min_tier, settings),
        "kinds": json.dumps(["ip", "cidr"] if spec.kind == "ip" else ["domain"]),
        "categories": json.dumps(sorted(spec.categories)),
        "limit": spec.max_entries or -1,
    }
    for row in conn.execute(_SELECT, params):
        item = to_scored(row, settings)
        if item is not None:
            yield item


def _attributions(
    source_ids: Collection[str], sources: Mapping[str, Source]
) -> tuple[Attribution, ...]:
    ordered = sorted(source_ids, key=lambda source_id: sources[source_id].name)
    return tuple(
        Attribution(sources[sid].name, sources[sid].licence, sources[sid].licence_url)
        for sid in ordered
    )
