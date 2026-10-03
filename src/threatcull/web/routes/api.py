# SPDX-License-Identifier: AGPL-3.0-only
"""JSON API: Sources, Outputs, Allowlist, Runs, Settings, Lookup, ``/me``.

Each resource has its own small dict-building function below: an explicit
allow-list of fields, not a generic dataclass dump. A new field added to
``Source``, ``OutputSpec``, ``Run`` or ``Settings`` is therefore invisible to
this API until someone deliberately adds it here — most importantly, nothing
ever exposes ``outputs.feed_token_hash`` by accident.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from threatcull.clock import utcnow
from threatcull.datadir import storage_bytes
from threatcull.home_detect import Candidate, public_ip_candidate
from threatcull.lookup import LookupResult, lookup
from threatcull.store.allowlist import AllowlistEntry, add_entry, builtin_entries, operator_entries
from threatcull.store.allowlist import remove_entry as store_remove_entry
from threatcull.store.errors import NotFoundError
from threatcull.store.outputs import OutputSpec, list_outputs
from threatcull.store.outputs import rotate_token as store_rotate_token
from threatcull.store.runs import Run, recent_runs
from threatcull.store.settings import Settings, load_settings
from threatcull.store.sources import Source, list_sources
from threatcull.store.sources import set_enabled as store_set_enabled
from threatcull.web.deps import (
    check_csrf,
    get_conn,
    home_detector,
    notify_sources_changed,
    public_ip_fetcher_factory,
    require_api_user,
)
from threatcull.web.schemas import AllowlistEntryIn, SourceEnableIn
from threatcull.web.status import build_status

router = APIRouter(prefix="/api/v1")

DEFAULT_RUNS_LIMIT = 50
MIN_RUNS_LIMIT = 1
MAX_RUNS_LIMIT = 200


def _source_json(source: Source) -> dict[str, Any]:
    return {
        "id": source.id,
        "name": source.name,
        "family": source.family,
        "url": source.url,
        "format": source.format,
        "kind": source.kind,
        "role": source.role,
        "category": source.category,
        "refresh_minutes": source.refresh_minutes,
        "custom": source.custom,
        "enabled": source.enabled,
        "disabled_reason": source.disabled_reason,
        "last_success_at": source.last_success_at,
        "last_attempt_at": source.last_attempt_at,
        "last_error": source.last_error,
    }


def _output_json(output: OutputSpec) -> dict[str, Any]:
    return {
        "name": output.name,
        "kind": output.kind,
        "categories": sorted(output.categories),
        "min_tier": output.min_tier,
        "max_entries": output.max_entries,
        "format": output.format,
        "last_count": output.last_count,
        "last_published_at": output.last_published_at,
        # The Feed Token is never readable: append "/<feed-token>" or "?token=<feed-token>".
        "feed_path": f"/o/{output.name}",
    }


def _allowlist_json(entry: AllowlistEntry) -> dict[str, Any]:
    return {
        "value": entry.value,
        "kind": entry.kind,
        "note": entry.note,
        "origin": entry.origin,
        "mine": entry.mine,
    }


def _candidate_json(candidate: Candidate) -> dict[str, Any]:
    return {"value": candidate.value, "reason": candidate.reason}


def _run_json(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "type": run.type,
        "source_id": run.source_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "duration_seconds": run.duration_seconds,
        "timings": run.timings,
        "status": run.status,
        "counts": run.counts,
        "error": run.error,
        "home_hits": [
            {"value": value, "source_ids": sources.split(",")} for value, sources in run.home_hits
        ],
    }


def _lookup_json(result: LookupResult, outputs: list[OutputSpec]) -> dict[str, Any]:
    caps = {spec.name: spec.max_entries for spec in outputs}
    allowlisted = result.allowlisted_by
    return {
        "value": result.value,
        "kind": result.kind,
        "score": result.score,
        "tier": result.tier,
        "sightings": [
            {
                "source_id": s.source_id,
                "source_name": s.source_name,
                "source_enabled": s.enabled,
                "current": s.current,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in result.sightings
        ],
        "allowlisted_by": _allowlist_json(allowlisted) if allowlisted else None,
        "eligible_outputs": [
            {"name": name, "max_entries": caps.get(name)} for name in result.eligible_outputs
        ],
    }


def _settings_json(settings: Settings) -> dict[str, Any]:
    return {
        "active_window_days": settings.active_window_days,
        "retention_days": settings.retention_days,
        "stale_after_hours": settings.stale_after_hours,
        "tier_high": settings.tier_high,
        "tier_medium": settings.tier_medium,
        "max_shrink": settings.max_shrink,
        "max_stale_ratio": settings.max_stale_ratio,
    }


@router.get("/me")
def me(user: Annotated[str, Depends(require_api_user)]) -> dict[str, str]:
    return {"username": user}


@router.get("/status")
def api_status(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> dict[str, Any]:
    """What runs now (step, Source, elapsed, trigger) and what comes next."""
    status = build_status(
        conn, request.app.state.runner, getattr(request.app.state, "scheduler", None)
    )
    database, outputs = storage_bytes(request.app.state.data_dir)
    return {**status.to_json(), "database_bytes": database, "outputs_bytes": outputs}


@router.get("/sources")
def api_sources(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    return [_source_json(source) for source in list_sources(conn)]


@router.post("/sources/{source_id}", dependencies=[Depends(check_csrf)])
def api_set_source_enabled(
    request: Request,
    source_id: str,
    body: SourceEnableIn,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> dict[str, Any]:
    try:
        source = store_set_enabled(conn, source_id, body.enabled)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    notify_sources_changed(request)
    return _source_json(source)


@router.get("/outputs")
def api_outputs(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    return [_output_json(output) for output in list_outputs(conn)]


@router.post("/outputs/{name}/rotate", dependencies=[Depends(check_csrf)])
def api_rotate_output_token(
    name: str,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    response: Response,
) -> dict[str, Any]:
    try:
        token = store_rotate_token(conn, name)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # A Feed Token is shown once; never let a cache keep a copy of this body.
    response.headers["Cache-Control"] = "no-store"
    return {"name": name, "token": token}


@router.get("/allowlist")
def api_allowlist(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    entries = [*operator_entries(conn), *builtin_entries(conn)]
    return [_allowlist_json(entry) for entry in entries]


@router.post("/allowlist", dependencies=[Depends(check_csrf)])
def api_add_allowlist_entry(
    body: AllowlistEntryIn,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> dict[str, Any]:
    try:
        entry = add_entry(conn, body.value, body.note, mine=body.mine, now=utcnow())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _allowlist_json(entry)


@router.delete("/allowlist", dependencies=[Depends(check_csrf)])
def api_remove_allowlist_entry(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    value: Annotated[str, Query()],
) -> dict[str, Any]:
    try:
        store_remove_entry(conn, value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"value": value, "removed": True}


@router.post("/allowlist/detect", dependencies=[Depends(check_csrf)])
def api_detect_mine(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    public_ip: bool = False,
) -> dict[str, Any]:
    """Suggest your own public addresses; adds nothing. ``public_ip=true`` asks api.ipify.org."""
    existing = operator_entries(conn)
    hosts = [request.url.hostname] if request.url.hostname else []
    candidates = home_detector(request)(existing=existing, extra_hosts=hosts)
    if public_ip:
        _, candidate = public_ip_candidate(
            public_ip_fetcher_factory(request)(), existing=existing, found=candidates
        )
        if candidate is not None:
            candidates.append(candidate)
    return {"candidates": [_candidate_json(candidate) for candidate in candidates]}


@router.get("/runs")
def api_runs(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    limit: Annotated[int, Query(ge=MIN_RUNS_LIMIT, le=MAX_RUNS_LIMIT)] = DEFAULT_RUNS_LIMIT,
) -> list[dict[str, Any]]:
    return [_run_json(run) for run in recent_runs(conn, limit)]


@router.get("/settings")
def api_settings(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> dict[str, Any]:
    return _settings_json(load_settings(conn))


@router.get("/lookup")
def api_lookup(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    q: Annotated[str, Query(max_length=512)],
) -> dict[str, Any]:
    result = lookup(conn, q, now=utcnow())
    if result is None:
        raise HTTPException(status_code=400, detail="not a public IP, CIDR or domain")
    return _lookup_json(result, list_outputs(conn))
