# SPDX-License-Identifier: AGPL-3.0-only
"""Compile: Sightings → Allowlist → score → Tier → select → render → publish."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from threatcull.clock import ts
from threatcull.outputs.files import atomic_write, output_path
from threatcull.outputs.render import Attribution, RenderContext, render
from threatcull.outputs.select import select
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import ScoredIndicator, scored_indicators
from threatcull.store.allowlist import builtin_entries, operator_entries
from threatcull.store.outputs import list_outputs, record_published
from threatcull.store.runs import finish_run, start_run
from threatcull.store.settings import Settings, load_settings
from threatcull.store.sightings import prune
from threatcull.store.sources import Source, list_sources


@dataclass(frozen=True, slots=True)
class CompileReport:
    status: Literal["ok", "blocked"]
    counts: dict[str, int]
    reasons: tuple[str, ...] = ()
    allowlisted: int = 0
    stale_sources: tuple[str, ...] = ()


def shrink_reasons(
    previous: Mapping[str, int | None],
    new: Mapping[str, int],
    *,
    stale: int,
    enabled: int,
    settings: Settings,
) -> list[str]:
    reasons: list[str] = []
    if enabled and stale / enabled > settings.max_stale_ratio:
        reasons.append(
            f"{stale} of {enabled} enabled blocklist Sources are Stale "
            f"(limit {settings.max_stale_ratio:.0%})"
        )
    for name, count in new.items():
        before = previous.get(name)
        if before and count < before * (1 - settings.max_shrink):
            reasons.append(
                f"Output {name} would shrink from {before} to {count} "
                f"(limit {settings.max_shrink:.0%})"
            )
    return reasons


def compile_outputs(
    conn: sqlite3.Connection, out_dir: Path, *, now: datetime, force: bool = False
) -> CompileReport:
    run_id = start_run(conn, "compile", now=now)
    try:
        report = _compile(conn, out_dir, now=now, force=force)
    except Exception as exc:
        finish_run(conn, run_id, "failed", now=now, error=f"{type(exc).__name__}: {exc}")
        raise
    finish_run(
        conn,
        run_id,
        report.status,
        now=now,
        counts=report.counts,
        error="; ".join(report.reasons) or None,
    )
    return report


def _compile(
    conn: sqlite3.Connection, out_dir: Path, *, now: datetime, force: bool
) -> CompileReport:
    settings = load_settings(conn)
    prune(conn, now=now, retention_days=settings.retention_days)
    blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    cutoff = ts(now - timedelta(hours=settings.stale_after_hours))
    stale = tuple(
        s.id for s in blocklists if s.last_success_at is None or s.last_success_at < cutoff
    )
    allowlist = Allowlist([*operator_entries(conn), *builtin_entries(conn)])
    scored = scored_indicators(conn, now=now, settings=settings)
    kept = [item for item in scored if allowlist.match(item.value, item.kind) is None]
    sources = {source.id: source for source in list_sources(conn)}
    specs = list_outputs(conn)
    rendered: dict[str, tuple[Path, str, int]] = {}
    for spec in specs:
        items = select(kept, spec)
        ctx = RenderContext(
            output_name=spec.name,
            generated_at=ts(now),
            attributions=_attributions(items, sources),
            source_names={source_id: source.name for source_id, source in sources.items()},
        )
        rendered[spec.name] = (
            output_path(out_dir, spec),
            render(spec.format, items, ctx),
            len(items),
        )
    counts = {name: count for name, (_, _, count) in rendered.items()}
    reasons = shrink_reasons(
        {spec.name: spec.last_count for spec in specs},
        counts,
        stale=len(stale),
        enabled=len(blocklists),
        settings=settings,
    )
    allowlisted = len(scored) - len(kept)
    if reasons and not force:
        return CompileReport("blocked", counts, tuple(reasons), allowlisted, stale)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, (path, text, count) in rendered.items():
        atomic_write(path, text)
        record_published(conn, name, count, now=now)
    return CompileReport("ok", counts, tuple(reasons), allowlisted, stale)


def _attributions(
    items: Sequence[ScoredIndicator], sources: Mapping[str, Source]
) -> tuple[Attribution, ...]:
    ids = sorted({sid for item in items for sid in item.source_ids}, key=lambda s: sources[s].name)
    return tuple(
        Attribution(sources[sid].name, sources[sid].licence, sources[sid].licence_url)
        for sid in ids
    )
