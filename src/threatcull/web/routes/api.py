# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only JSON API: Sources, Outputs, Runs, Settings, and ``/api/v1/me``."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from enum import Enum
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from threatcull.store.outputs import list_outputs
from threatcull.store.runs import recent_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import list_sources
from threatcull.web.deps import get_conn, require_api_user

router = APIRouter(prefix="/api/v1")

DEFAULT_RUNS_LIMIT = 50
MIN_RUNS_LIMIT = 1
MAX_RUNS_LIMIT = 200


def _json_safe(value: Any) -> Any:
    """Make one dataclass-field value JSON-serialisable: enums and sets/tuples."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, frozenset | set):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    return value


def _row(obj: Any) -> dict[str, Any]:
    """A flat dataclass instance as a JSON-safe dict (fields only, never a DB row)."""
    return {key: _json_safe(value) for key, value in asdict(obj).items()}


@router.get("/me")
def me(user: Annotated[str, Depends(require_api_user)]) -> dict[str, str]:
    return {"username": user}


@router.get("/sources")
def api_sources(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    return [_row(source) for source in list_sources(conn)]


@router.get("/outputs")
def api_outputs(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> list[dict[str, Any]]:
    # OutputSpec never carries feed_token_hash: only the Feed Token routes
    # (web/routes/feeds.py) touch the hashed token, via verify_token/rotate_token.
    return [_row(output) for output in list_outputs(conn)]


@router.get("/runs")
def api_runs(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
    limit: Annotated[int, Query(ge=MIN_RUNS_LIMIT, le=MAX_RUNS_LIMIT)] = DEFAULT_RUNS_LIMIT,
) -> list[dict[str, Any]]:
    return [_row(run) for run in recent_runs(conn, limit)]


@router.get("/settings")
def api_settings(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_api_user)],
) -> dict[str, Any]:
    return _row(load_settings(conn))
