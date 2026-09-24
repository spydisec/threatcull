# SPDX-License-Identifier: AGPL-3.0-only
"""Compile: Sightings → score → Allowlist → Tier → select → render → publish.

Scoring happens in a SQLite TEMP table and every Output is streamed to a temp file,
so memory stays bounded however many Indicators the Sources list.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from threatcull.clock import ts
from threatcull.outputs.stream import StagedOutput, home_hits, mark_allowlisted, stage_output
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import create_scored_table, drop_scored_table
from threatcull.store.allowlist import builtin_entries, operator_entries
from threatcull.store.home import home_allow_entries
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
    # Scored Indicators a Home Network entry excluded: a Source lists our own network.
    home_hit_count: int = 0
    home_hits: tuple[tuple[str, str], ...] = ()  # (value, Source ids), first HOME_HITS_CAP


HOME_HITS_CAP = 100


def stale_source_ids(
    sources: Sequence[Source], *, now: datetime, settings: Settings
) -> tuple[str, ...]:
    """Ids of ``sources`` whose last success is missing or older than ``stale_after_hours``.

    The Stale-Source rule Compile uses for its guard; the dashboard reuses this
    instead of re-deriving it.
    """
    cutoff = ts(now - timedelta(hours=settings.stale_after_hours))
    return tuple(s.id for s in sources if s.last_success_at is None or s.last_success_at < cutoff)


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
    counts = dict(report.counts)
    if report.home_hit_count:
        counts["home_hits"] = report.home_hit_count
    finish_run(
        conn,
        run_id,
        report.status,
        now=now,
        counts=counts,
        error="; ".join(report.reasons) or None,
        home_hits=report.home_hits,
    )
    return report


def _compile(
    conn: sqlite3.Connection, out_dir: Path, *, now: datetime, force: bool
) -> CompileReport:
    settings = load_settings(conn)
    prune(conn, now=now, retention_days=settings.retention_days)
    blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    stale = stale_source_ids(blocklists, now=now, settings=settings)
    create_scored_table(conn, now=now, settings=settings)
    staged: list[StagedOutput] = []
    try:
        allowlisted = mark_allowlisted(
            conn,
            Allowlist([*operator_entries(conn), *builtin_entries(conn)]),
            home=Allowlist(home_allow_entries(conn)),
        )
        hit_count, hits = home_hits(conn, HOME_HITS_CAP)
        sources = {source.id: source for source in list_sources(conn)}
        specs = list_outputs(conn)
        out_dir.mkdir(parents=True, exist_ok=True)
        for spec in specs:
            staged.append(
                stage_output(
                    conn, spec, out_dir, generated_at=ts(now), sources=sources, settings=settings
                )
            )
        counts = {output.name: output.count for output in staged}
        reasons = shrink_reasons(
            {spec.name: spec.last_count for spec in specs},
            counts,
            stale=len(stale),
            enabled=len(blocklists),
            settings=settings,
        )
        if reasons and not force:
            return CompileReport(
                "blocked", counts, tuple(reasons), allowlisted, stale, hit_count, hits
            )
        for output in staged:
            output.tmp.replace(output.path)
            record_published(conn, output.name, output.count, now=now)
        return CompileReport("ok", counts, tuple(reasons), allowlisted, stale, hit_count, hits)
    finally:
        # Blocked or failed: nothing is published. Published temp files are already gone.
        for output in staged:
            output.tmp.unlink(missing_ok=True)
        drop_scored_table(conn)
