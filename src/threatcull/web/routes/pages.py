# SPDX-License-Identifier: AGPL-3.0-only
"""HTML pages: dashboard, Sources, Outputs, Allowlist, Runs, Lookup and Settings."""

from __future__ import annotations

import sqlite3
from collections import Counter
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request
from pydantic import ValidationError
from starlette.responses import RedirectResponse, Response

from threatcull.clock import ts, utcnow
from threatcull.compiling import stale_source_ids
from threatcull.lookup import lookup, output_labels
from threatcull.store.allowlist import add_entry, builtin_entries, operator_entries, remove_entry
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import OutputSpec, create_output, list_outputs, rotate_token
from threatcull.store.runs import last_run, recent_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import add_custom_source, list_sources, set_business_mode
from threatcull.store.sources import set_enabled as store_set_enabled
from threatcull.web.deps import check_csrf, get_conn, notify_sources_changed, require_user
from threatcull.web.jobs import PipelineRunner
from threatcull.web.scheduler import Scheduler
from threatcull.web.schemas import AllowlistEntryIn, CustomSourceIn, OutputCreateIn
from threatcull.web.templating import flash, render, render_fragment

router = APIRouter()

RUNS_PAGE_LIMIT = 50
LOOKUP_MAX_LENGTH = 512  # same cap as /api/v1/lookup
RUN_STARTED = "Run started."
ALREADY_RUNNING = "A run is already in progress."


def _runner(request: Request) -> PipelineRunner:
    runner: PipelineRunner = request.app.state.runner
    return runner


def _run_status(request: Request) -> dict[str, Any]:
    runner = _runner(request)
    return {"running": runner.is_running(), "last_result": runner.last_result}


def _notify_sources_changed(request: Request) -> None:
    """Tell the scheduler (if running) that Sources changed; see ``notify_sources_changed``."""
    notify_sources_changed(request)


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
    scheduler: Scheduler | None = getattr(request.app.state, "scheduler", None)
    next_run = scheduler.next_compile_at() if scheduler is not None else None
    next_compile = ts(next_run) if next_run is not None else None
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
            "scheduler_on": scheduler is not None,
            "next_compile_at": next_compile,
            **_run_status(request),
        },
    )


@router.get("/partials/status")
def status_fragment(
    request: Request,
    user: Annotated[str, Depends(require_user)],
) -> Response:
    """Run status for the dashboard; while a run is going it re-polls itself every 3 s."""
    return render_fragment(request, "_status.html", _run_status(request))


@router.get("/sources")
def sources_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "sources.html", {"sources": list_sources(conn)})


def _outputs_context(request: Request, conn: sqlite3.Connection) -> dict[str, Any]:
    return {"outputs": list_outputs(conn), "base_url": str(request.base_url)}


@router.get("/outputs")
def outputs_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "outputs.html", _outputs_context(request, conn))


@router.post("/outputs/{name}/rotate", dependencies=[Depends(check_csrf)])
def rotate_output_token_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    name: str,
) -> Response:
    try:
        token = rotate_token(conn, name)
    except NotFoundError as exc:
        context = _outputs_context(request, conn)
        context["error"] = str(exc)
        return render(request, "outputs.html", context, status_code=404)
    context = _outputs_context(request, conn)
    context.update({"revealed_name": name, "revealed_token": token, "revealed_rotated": True})
    return render(request, "outputs.html", context, headers={"Cache-Control": "no-store"})


def _create_output_error(request: Request, conn: sqlite3.Connection, message: str) -> Response:
    context = _outputs_context(request, conn)
    context["create_error"] = message
    return render(request, "outputs.html", context, status_code=400)


@router.post("/outputs", dependencies=[Depends(check_csrf)])
def create_output_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    *,
    # Defaulted to "" (not required): an empty *required* Form field is
    # treated by FastAPI as missing (a 422 that would bypass our inline 400),
    # so these fall through to OutputCreateIn's own validation instead.
    name: Annotated[str, Form()] = "",
    kind: Annotated[str, Form()] = "",
    categories: Annotated[tuple[str, ...], Form()] = (),
    min_tier: Annotated[str, Form()] = "high",
    max_entries: Annotated[str, Form()] = "",
    format: Annotated[str, Form()] = "plain",
) -> Response:
    max_entries_value: int | None = None
    if max_entries.strip():
        try:
            max_entries_value = int(max_entries.strip())
        except ValueError:
            return _create_output_error(request, conn, "max_entries must be a whole number")
    try:
        payload = OutputCreateIn(
            name=name,
            kind=kind,
            categories=categories,
            min_tier=min_tier,
            max_entries=max_entries_value,
            format=format,
        )
    except ValidationError as exc:
        return _create_output_error(request, conn, _validation_message(exc))
    try:
        spec = OutputSpec(
            payload.name,
            payload.kind,
            frozenset(payload.categories),
            payload.min_tier,
            payload.max_entries,
            payload.format,
        )
    except ValueError as exc:
        return _create_output_error(request, conn, str(exc))
    try:
        token = create_output(conn, spec)
    except sqlite3.IntegrityError:
        message = f"an Output named {payload.name!r} already exists"
        return _create_output_error(request, conn, message)
    context = _outputs_context(request, conn)
    context.update(
        {"revealed_name": payload.name, "revealed_token": token, "revealed_rotated": False}
    )
    return render(request, "outputs.html", context, headers={"Cache-Control": "no-store"})


@router.get("/runs")
def runs_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "runs.html", _runs_context(request, conn))


def _runs_context(request: Request, conn: sqlite3.Connection) -> dict[str, Any]:
    return {"runs": recent_runs(conn, RUNS_PAGE_LIMIT), **_run_status(request)}


@router.post("/runs/now", dependencies=[Depends(check_csrf)])
def run_now(
    request: Request,
    user: Annotated[str, Depends(require_user)],
) -> Response:
    started = _runner(request).start_background()
    flash(request, RUN_STARTED if started else ALREADY_RUNNING)
    return RedirectResponse("/runs", status_code=303)


@router.post("/runs/compile-force", dependencies=[Depends(check_csrf)])
def compile_force(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    confirm: Annotated[bool, Form()] = False,
) -> Response:
    """Compile with ``force=True`` (overrides a blocked Shrink Guard); no Fetch."""
    if not confirm:
        context = _runs_context(request, conn)
        context["force_error"] = "Tick the confirm box to force a Compile."
        return render(request, "runs.html", context, status_code=400)
    result = _runner(request).compile_only(force=True)
    if result.status == "already_running":
        flash(request, ALREADY_RUNNING)
    else:
        flash(request, f"Compile forced: {result.status}.")
    return RedirectResponse("/runs", status_code=303)


@router.get("/lookup")
def lookup_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    q: str = "",
) -> Response:
    context: dict[str, Any] = {"q": q, "result": None, "labels": (), "invalid": None}
    if len(q) > LOOKUP_MAX_LENGTH:
        context["invalid"] = f"That value is too long (over {LOOKUP_MAX_LENGTH} characters)."
    elif q:
        result = lookup(conn, q, now=utcnow())
        if result is None:
            context["invalid"] = f"{q.strip()!r} is not a public IP, CIDR or domain."
        else:
            context["result"] = result
            context["labels"] = output_labels(conn, result.eligible_outputs)
    return render(request, "lookup.html", context)


def _allowlist_context(conn: sqlite3.Connection) -> dict[str, Any]:
    builtin_counts = Counter(entry.origin for entry in builtin_entries(conn))
    return {
        "operator_entries": operator_entries(conn),
        "allowlist_sources": list_sources(conn, role="allowlist"),
        "builtin_counts": builtin_counts,
    }


@router.get("/allowlist")
def allowlist_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "allowlist.html", _allowlist_context(conn))


def _allowlist_error(
    request: Request,
    conn: sqlite3.Connection,
    message: str,
    *,
    value: str,
    note: str,
    status_code: int,
) -> Response:
    context = _allowlist_context(conn)
    context.update({"error": message, "value": value, "note": note})
    return render(request, "allowlist.html", context, status_code=status_code)


@router.post("/allowlist", dependencies=[Depends(check_csrf)])
def add_allowlist_entry_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    # Defaults to "" (not required): FastAPI treats an empty *required* Form
    # field as missing (a 422), which would bypass our own inline 400 for an
    # empty value; letting it through and relying on AllowlistEntryIn's own
    # min_length=1 check keeps the 400 path reachable.
    value: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
) -> Response:
    try:
        payload = AllowlistEntryIn(value=value, note=note)
    except ValidationError as exc:
        return _allowlist_error(
            request, conn, _validation_message(exc), value=value, note=note, status_code=400
        )
    try:
        add_entry(conn, payload.value, payload.note, now=utcnow())
    except ValueError as exc:
        return _allowlist_error(
            request, conn, str(exc), value=payload.value, note=payload.note, status_code=400
        )
    return RedirectResponse("/allowlist", status_code=303)


@router.post("/allowlist/remove", dependencies=[Depends(check_csrf)])
def remove_allowlist_entry_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    value: Annotated[str, Form()] = "",
) -> Response:
    try:
        remove_entry(conn, value)
    except ValueError as exc:
        return _allowlist_error(request, conn, str(exc), value=value, note="", status_code=400)
    except NotFoundError as exc:
        return _allowlist_error(request, conn, str(exc), value=value, note="", status_code=404)
    return RedirectResponse("/allowlist", status_code=303)


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
