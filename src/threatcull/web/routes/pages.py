# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only dashboard, Sources, Outputs and Runs pages."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from threatcull.clock import utcnow
from threatcull.compiling import stale_source_ids
from threatcull.store.outputs import list_outputs
from threatcull.store.runs import Run, recent_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import list_sources
from threatcull.web.deps import get_conn, require_user
from threatcull.web.templating import render

router = APIRouter()

# How many Runs the dashboard scans to find the last Compile Run. Generous
# enough that a Compile is never missed among interleaved Fetch Runs, without
# scanning the whole table.
LAST_COMPILE_SEARCH_LIMIT = 100
RUNS_PAGE_LIMIT = 50


def _last_compile_run(conn: sqlite3.Connection) -> Run | None:
    for run in recent_runs(conn, LAST_COMPILE_SEARCH_LIMIT):
        if run.type == "compile":
            return run
    return None


@router.get("/")
def dashboard(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    settings = load_settings(conn)
    enabled_blocklists = list_sources(conn, enabled_only=True, role="blocklist")
    stale_ids = stale_source_ids(enabled_blocklists, now=utcnow(), settings=settings)
    allowlist_sources = list_sources(conn, role="allowlist")
    return render(
        request,
        "dashboard.html",
        {
            "business_mode": settings.business_mode,
            "enabled_blocklist_count": len(enabled_blocklists),
            "stale_count": len(stale_ids),
            "allowlist_count": len(allowlist_sources),
            "last_compile": _last_compile_run(conn),
            "outputs": list_outputs(conn),
        },
    )


@router.get("/sources")
def sources_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "sources.html", {"sources": list_sources(conn)})


@router.get("/outputs")
def outputs_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(
        request,
        "outputs.html",
        {"outputs": list_outputs(conn), "base_url": str(request.base_url)},
    )


@router.get("/runs")
def runs_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "runs.html", {"runs": recent_runs(conn, RUNS_PAGE_LIMIT)})
