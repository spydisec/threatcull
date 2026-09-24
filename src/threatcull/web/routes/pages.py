# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only dashboard, Sources, Outputs and Runs pages."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import ValidationError
from starlette.responses import RedirectResponse, Response

from threatcull.clock import utcnow
from threatcull.compiling import stale_source_ids
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import list_outputs
from threatcull.store.runs import last_run, recent_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import add_custom_source, list_sources, set_business_mode
from threatcull.store.sources import set_enabled as store_set_enabled
from threatcull.web.deps import check_csrf, get_conn, require_user
from threatcull.web.schemas import CustomSourceIn
from threatcull.web.templating import render, render_fragment

router = APIRouter()

RUNS_PAGE_LIMIT = 50


def _notify_sources_changed(request: Request) -> None:
    """Task 8's hook, if wired up; a no-op default lives on the app state."""
    on_changed = getattr(request.app.state, "on_sources_changed", None)
    if on_changed is not None:
        on_changed()


def _validation_message(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
    )


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
            "last_compile": last_run(conn, "compile"),
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


def _apply_enabled_change(
    request: Request,
    conn: sqlite3.Connection,
    source_id: str,
    enabled: bool,
    *,
    acknowledge_restricted: bool,
) -> Response:
    """Shared body of the enable/disable handlers below.

    ``PolicyError``/``NotFoundError`` re-render the full Sources page with the
    message (400/404); on success, an htmx request gets just the updated row
    back, everyone else gets the usual ``303`` to ``/sources``.
    """
    try:
        source = store_set_enabled(
            conn, source_id, enabled, acknowledge_restricted=acknowledge_restricted
        )
    except NotFoundError as exc:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "error": str(exc)},
            status_code=404,
        )
    except PolicyError as exc:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "error": str(exc)},
            status_code=400,
        )
    _notify_sources_changed(request)
    if request.headers.get("HX-Request") == "true":
        return render_fragment(request, "_source_row.html", {"source": source})
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/{source_id}/enable", dependencies=[Depends(check_csrf)])
def enable_source(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    source_id: str,
    acknowledge_restricted: Annotated[bool, Form()] = False,
) -> Response:
    return _apply_enabled_change(
        request, conn, source_id, True, acknowledge_restricted=acknowledge_restricted
    )


@router.post("/sources/{source_id}/disable", dependencies=[Depends(check_csrf)])
def disable_source(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    source_id: str,
) -> Response:
    return _apply_enabled_change(request, conn, source_id, False, acknowledge_restricted=False)


@router.post("/sources/custom", dependencies=[Depends(check_csrf)])
def add_custom_source_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    *,
    id: Annotated[str, Form()],
    name: Annotated[str, Form()],
    url: Annotated[str, Form()],
    format: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    category: Annotated[str, Form()],
    csv_column: Annotated[int, Form()] = 0,
    json_keys: Annotated[str, Form()] = "",
    business_use: Annotated[str, Form()] = "unknown",
) -> Response:
    keys = tuple(key.strip() for key in json_keys.split(",") if key.strip())
    try:
        payload = CustomSourceIn(
            id=id,
            name=name,
            url=url,
            format=format,
            kind=kind,
            category=category,
            csv_column=csv_column,
            json_keys=keys,
            business_use=business_use,
        )
    except ValidationError as exc:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "custom_error": _validation_message(exc)},
            status_code=400,
        )
    try:
        add_custom_source(
            conn,
            source_id=payload.id,
            name=payload.name,
            url=payload.url,
            fmt=payload.format,
            kind=payload.kind,
            category=payload.category,
            csv_column=payload.csv_column,
            json_keys=payload.json_keys,
            business_use=payload.business_use,
        )
    except ValueError as exc:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "custom_error": str(exc)},
            status_code=400,
        )
    _notify_sources_changed(request)
    return RedirectResponse("/sources", status_code=303)


@router.get("/settings")
def settings_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(
        request, "settings.html", {"settings": load_settings(conn), "disabled_sources": []}
    )


@router.post("/settings/business-mode", dependencies=[Depends(check_csrf)])
def set_business_mode_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    on: Annotated[bool, Form()] = False,
) -> Response:
    disabled = set_business_mode(conn, on)
    _notify_sources_changed(request)
    return render(
        request,
        "settings.html",
        {"settings": load_settings(conn), "disabled_sources": disabled},
    )
