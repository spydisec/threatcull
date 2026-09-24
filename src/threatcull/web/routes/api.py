# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only JSON API: Sources, Outputs, Runs, Settings, and ``/api/v1/me``.

Each resource has its own small dict-building function below: an explicit
allow-list of fields, not a generic dataclass dump. A new field added to
``Source``, ``OutputSpec``, ``Run`` or ``Settings`` is therefore invisible to
this API until someone deliberately adds it here — most importantly, nothing
ever exposes ``outputs.feed_token_hash`` by accident.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import OutputSpec, list_outputs
from threatcull.store.runs import Run, recent_runs
from threatcull.store.settings import Settings, load_settings
from threatcull.store.sources import Source, list_sources
from threatcull.store.sources import set_enabled as store_set_enabled
from threatcull.web.deps import check_csrf, get_conn, require_api_user
from threatcull.web.schemas import SourceEnableIn

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
        "licence_class": source.licence_class.value,
        "business_use": source.business_use.value,
        "licence": source.licence,
        "licence_url": source.licence_url,
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
    }


def _run_json(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "type": run.type,
        "source_id": run.source_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "counts": run.counts,
        "error": run.error,
    }


def _settings_json(settings: Settings) -> dict[str, Any]:
    return {
        "business_mode": settings.business_mode,
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
        source = store_set_enabled(
            conn, source_id, body.enabled, acknowledge_restricted=body.acknowledge_restricted
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    on_changed = getattr(request.app.state, "on_sources_changed", None)
    if on_changed is not None:
        on_changed()
    return _source_json(source)


@router.get("/outputs")
def api_outputs(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    return [_output_json(output) for output in list_outputs(conn)]


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
