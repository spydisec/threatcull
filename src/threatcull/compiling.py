# SPDX-License-Identifier: AGPL-3.0-only
"""Compile: Sightings → score → Allowlist → Tier → select → render → publish.

Scoring happens in a SQLite TEMP table and every Output is streamed to a temp file,
so memory stays bounded however many Indicators the Sources list.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from threatcull.clock import ts
from threatcull.outputs.stream import StagedOutput, home_hits, mark_allowlisted, stage_output
from threatcull.policy.allowlist import Allowlist
from threatcull.policy.scoring import create_scored_table, drop_scored_table
from threatcull.policy.stats import CompileStats, compile_stats
from threatcull.store.allowlist import builtin_entries, mine_entries, operator_entries
from threatcull.store.outputs import OutputSpec, list_outputs, record_published
from threatcull.store.runs import finish_run, start_run
from threatcull.store.settings import Settings, load_settings
from threatcull.store.sightings import prune
from threatcull.store.sources import Source, list_sources
from threatcull.timing import StageTimer


@dataclass(frozen=True, slots=True)
class CompileReport:
    status: Literal["ok", "blocked"]
    counts: dict[str, int]
    reasons: tuple[str, ...] = ()
    allowlisted: int = 0
    stale_sources: tuple[str, ...] = ()
    # Scored Indicators an own-network entry excluded: a Source lists the operator's network.
    home_hit_count: int = 0
    home_hits: tuple[tuple[str, str], ...] = ()  # (value, Source ids), first HOME_HITS_CAP
    stats: CompileStats | None = None
    # Outputs whose shrink check was skipped: a Source that fed them was disabled.
    rebaselined: tuple[str, ...] = ()


HOME_HITS_CAP = 100


def stale_source_ids(
    sources: Sequence[Source], *, now: datetime, settings: Settings
) -> tuple[str, ...]:
    """Ids of ``sources`` whose last success is older than ``stale_after_hours``.

    A Source that never fetched successfully is not Stale: it has no Sightings,
    so it can't leave old data in the Outputs. Newly enabled Sources wait for
    the schedule (up to an hour) and must not block the Compile meanwhile; one
    that keeps failing shows as failing instead.

    The Stale-Source rule Compile uses for its guard; the dashboard reuses this
    instead of re-deriving it.
    """
    cutoff = ts(now - timedelta(hours=settings.stale_after_hours))
    return tuple(
        s.id for s in sources if s.last_success_at is not None and s.last_success_at < cutoff
    )


def is_frozen(source: Source, *, now: datetime, settings: Settings) -> bool:
    """True if ``source`` is a Frozen Source (#84).

    An enabled blocklist whose last Fetch succeeded but whose list has not gained
    or lost an Indicator for ``frozen_after_days``. Its Sightings still count:
    ThreatCull only warns, and the operator decides whether to disable it.
    Allowlists (vendor ranges change a few times a year) are never Frozen, and a
    failing Source shows as failing instead.
    """
    if not source.enabled or source.role != "blocklist" or source.last_error:
        return False
    if source.last_changed_at is None:
        return False
    return source.last_changed_at <= ts(now - timedelta(days=settings.frozen_after_days))


def frozen_source_ids(
    sources: Sequence[Source], *, now: datetime, settings: Settings
) -> tuple[str, ...]:
    """Ids of the Frozen Sources among ``sources``."""
    return tuple(s.id for s in sources if is_frozen(s, now=now, settings=settings))


def feeding_sources(spec: OutputSpec, blocklists: Sequence[Source]) -> frozenset[str]:
    """Enabled blocklist Sources whose kind and category can put Indicators in ``spec``."""
    return frozenset(
        s.id for s in blocklists if s.kind == spec.kind and s.category in spec.categories
    )


def rebaselined_outputs(specs: Sequence[OutputSpec], blocklists: Sequence[Source]) -> set[str]:
    """Outputs that lost a feeding Source since they were last published.

    The operator (or a Catalog update) disabled that Source, so a
    smaller Output is the intended new baseline, not an upstream failure.
    """
    return {
        spec.name
        for spec in specs
        if spec.last_sources is not None and spec.last_sources - feeding_sources(spec, blocklists)
    }


def shrink_reasons(
    previous: Mapping[str, int | None],
    new: Mapping[str, int],
    *,
    stale: int,
    enabled: int,
    settings: Settings,
    rebaselined: Set[str] = frozenset(),
) -> list[str]:
    reasons: list[str] = []
    if enabled and stale / enabled > settings.max_stale_ratio:
        reasons.append(
            f"{stale} of {enabled} enabled blocklist Sources are Stale "
            f"(limit {settings.max_stale_ratio:.0%})"
        )
    for name, count in new.items():
        if name in rebaselined:
            continue
        before = previous.get(name)
        if before and count < before * (1 - settings.max_shrink):
            reasons.append(
                f"Output {name} would shrink from {before} to {count} "
                f"(limit {settings.max_shrink:.0%})"
            )
    return reasons


# PRAGMA optimize reads at most this many rows per index when it re-analyses,
# so its cost stays small however many Sightings there are. (A PRAGMA takes no
# parameters, hence the literal.)
ANALYSIS_LIMIT = 1000
_SET_ANALYSIS_LIMIT = "PRAGMA analysis_limit = 1000"

log = logging.getLogger(__name__)


def optimize_database(conn: sqlite3.Connection) -> None:
    """Refresh SQLite's query-planner statistics after a Compile.

    The tables grow from nothing to millions of rows on a first run; without
    statistics the planner keeps guessing from the empty database. Best effort:
    a failure is logged and never fails the Compile.
    """
    try:
        conn.execute(_SET_ANALYSIS_LIMIT)
        conn.execute("PRAGMA optimize")
    except sqlite3.Error:
        log.warning("PRAGMA optimize after the Compile failed", exc_info=True)


def compile_outputs(
    conn: sqlite3.Connection, out_dir: Path, *, now: datetime, force: bool = False
) -> CompileReport:
    run_id = start_run(conn, "compile", now=now)
    timer = StageTimer()
    try:
        report = _compile(conn, out_dir, now=now, force=force, timer=timer)
    except Exception as exc:
        finish_run(
            conn,
            run_id,
            "failed",
            now=now,
            error=f"{type(exc).__name__}: {exc}",
            stats={"timings": timer.to_json()},
        )
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
        stats={**(report.stats.to_json() if report.stats else {}), "timings": timer.to_json()},
    )
    optimize_database(conn)
    return report


def _compile(
    conn: sqlite3.Connection, out_dir: Path, *, now: datetime, force: bool, timer: StageTimer
) -> CompileReport:
    settings = load_settings(conn)
    with timer.stage("prune"):
        prune(conn, now=now, retention_days=settings.retention_days)
    blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    stale = stale_source_ids(blocklists, now=now, settings=settings)
    with timer.stage("score"):
        create_scored_table(conn, now=now, settings=settings)
    staged: list[StagedOutput] = []
    try:
        with timer.stage("allowlist"):
            excluded = mark_allowlisted(
                conn,
                Allowlist([*operator_entries(conn), *builtin_entries(conn)]),
                home=Allowlist(mine_entries(conn)),
            )
            hit_count, hits = home_hits(conn, HOME_HITS_CAP)
        # `excluded` counts every excluded row, own-network entries included; the Allowlist
        # count operators see (CLI, dashboard) must name only Allowlist exclusions.
        allowlisted = excluded - hit_count
        with timer.stage("stats"):
            stats = compile_stats(conn, settings)
        sources = {source.id: source for source in list_sources(conn)}
        specs = list_outputs(conn)
        out_dir.mkdir(parents=True, exist_ok=True)
        with timer.stage("outputs"):
            for spec in specs:
                staged.append(
                    stage_output(
                        conn,
                        spec,
                        out_dir,
                        generated_at=ts(now),
                        sources=sources,
                        settings=settings,
                    )
                )
        counts = {output.name: output.count for output in staged}
        rebaselined = rebaselined_outputs(specs, blocklists)
        reasons = shrink_reasons(
            {spec.name: spec.last_count for spec in specs},
            counts,
            stale=len(stale),
            # Only Sources with data can be Stale, so only they count towards the ratio.
            enabled=sum(1 for source in blocklists if source.last_success_at is not None),
            settings=settings,
            rebaselined=rebaselined,
        )
        if reasons and not force:
            return CompileReport(
                "blocked", counts, tuple(reasons), allowlisted, stale, hit_count, hits, stats
            )
        feeds = {spec.name: feeding_sources(spec, blocklists) for spec in specs}
        with timer.stage("publish"):
            for output in staged:
                output.tmp.replace(output.path)
                record_published(
                    conn, output.name, output.count, now=now, sources=feeds[output.name]
                )
        return CompileReport(
            "ok",
            counts,
            tuple(reasons),
            allowlisted,
            stale,
            hit_count,
            hits,
            stats,
            tuple(sorted(rebaselined)),
        )
    finally:
        # Blocked or failed: nothing is published. Published temp files are already gone.
        for output in staged:
            output.tmp.unlink(missing_ok=True)
        drop_scored_table(conn)
