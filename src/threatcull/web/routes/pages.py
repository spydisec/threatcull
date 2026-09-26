# SPDX-License-Identifier: AGPL-3.0-only
"""HTML pages: dashboard, Sources, Outputs, Allowlist, Runs, Lookup, Settings."""

from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from pydantic import ValidationError
from starlette.responses import RedirectResponse, Response

from threatcull.clock import ts, utcnow
from threatcull.compiling import stale_source_ids
from threatcull.home_detect import public_ip_candidate
from threatcull.listfile import MAX_BYTES, parse_list_file, summary
from threatcull.lookup import lookup, output_labels
from threatcull.policy.stats import CompileStats
from threatcull.store.allowlist import (
    add_entry,
    builtin_entries,
    import_entries,
    operator_entries,
    remove_entry,
    set_mine,
)
from threatcull.store.config import apply_config, dump_config, parse_config
from threatcull.store.db import transaction
from threatcull.store.errors import NotFoundError, PolicyError
from threatcull.store.outputs import OutputSpec, create_output, list_outputs, rotate_token
from threatcull.store.runs import compile_history, last_run, recent_fetches, recent_runs
from threatcull.store.settings import load_settings
from threatcull.store.sources import (
    add_custom_source,
    get_source,
    list_sources,
    new_custom_id,
)
from threatcull.store.sources import set_enabled as store_set_enabled
from threatcull.web.dashboard import (
    FUNNEL_WIDTH,
    chart_data,
    funnel,
    health,
    output_changes,
    source_changes,
    source_rows,
)
from threatcull.web.deps import (
    check_csrf,
    current_user,
    get_conn,
    home_detector,
    notify_sources_changed,
    public_ip_fetcher_factory,
    require_user,
    web_file_url_error,
)
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


def _dashboard_context(request: Request, conn: sqlite3.Connection) -> dict[str, Any]:
    now = utcnow()
    settings = load_settings(conn)
    sources = list_sources(conn)
    names = {source.id: source.name for source in sources}
    blocklists = [s for s in sources if s.enabled and s.role == "blocklist"]
    stale_ids = stale_source_ids(blocklists, now=now, settings=settings)
    scheduler: Scheduler | None = getattr(request.app.state, "scheduler", None)
    next_run = scheduler.next_compile_at() if scheduler is not None else None
    last_compile = last_run(conn, "compile")
    # A failed Compile records no own-network hits; the alert must show the last
    # Compile that actually finished (ok or blocked), not go dark behind a failure.
    home_compile = last_run(conn, "compile", statuses=("ok", "blocked"))
    home_alerts = [
        (value, ", ".join(names.get(sid, sid) for sid in hit_sources.split(",")))
        for value, hit_sources in (home_compile.home_hits if home_compile else ())
    ]
    history = compile_history(conn, since=ts(now - timedelta(days=30)))
    stats = CompileStats.from_json(history[-1].stats) if history else None
    outputs = list_outputs(conn)
    context: dict[str, Any] = {
        "enabled_blocklist_count": len(blocklists),
        "failing_count": sum(1 for s in blocklists if s.last_error),
        "stale_count": len(stale_ids),
        "allowlist_count": sum(1 for s in sources if s.role == "allowlist"),
        "last_compile": last_compile,
        "health": health(last_compile, blocklists, len(stale_ids)),
        "home_alerts": home_alerts,
        "home_hit_count": home_compile.counts.get("home_hits", 0) if home_compile else 0,
        "outputs": outputs,
        "output_changes": output_changes(outputs, history),
        "source_changes": source_changes(recent_fetches(conn), {s.id: s.name for s in blocklists}),
        "scheduler_on": scheduler is not None,
        "next_compile_at": ts(next_run) if next_run is not None else None,
        "refreshed_at": ts(now),
        "stats": stats,
        **_run_status(request),
    }
    if stats is not None:
        context.update(
            {
                "stats_at": history[-1].finished_at,
                "funnel": funnel(stats),
                "funnel_width": FUNNEL_WIDTH,
                "source_rows": source_rows(stats, names),
                "chart_data": chart_data(stats, history, now=now),
            }
        )
    return context


@router.get("/partials/dashboard")
def dashboard_fragment(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render_fragment(request, "_dashboard_body.html", _dashboard_context(request, conn))


@router.get("/")
def dashboard(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "dashboard.html", _dashboard_context(request, conn))


# htmx stops polling when a response has this status (and still swaps the body).
HTMX_STOP_POLLING = 286


@router.get("/partials/status")
def status_fragment(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
) -> Response:
    """Run status for the dashboard; while a run is going it re-polls itself every 3 s.

    An expired session gets a one-line notice (status 286, so htmx stops
    polling) instead of the login page being swapped into the dashboard.
    """
    if current_user(request, conn) is None:
        return render_fragment(request, "_session_expired.html", status_code=HTMX_STOP_POLLING)
    return render_fragment(request, "_status.html", _run_status(request))


@router.get("/sources")
def sources_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    add: bool = False,
) -> Response:
    """``?add=1`` opens the "Add your own list" form (linked from the Allowlist page)."""
    return render(request, "sources.html", {"sources": list_sources(conn), "open_add": add})


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
    last_compile = last_run(conn, "compile")
    return {
        "runs": recent_runs(conn, RUNS_PAGE_LIMIT),
        "last_compile_status": last_compile.status if last_compile else None,
        **_run_status(request),
    }


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
        "candidates": None,
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
    *,
    # Defaults to "" (not required): FastAPI treats an empty *required* Form
    # field as missing (a 422), which would bypass our own inline 400 for an
    # empty value; letting it through and relying on AllowlistEntryIn's own
    # min_length=1 check keeps the 400 path reachable.
    value: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
    mine: Annotated[bool, Form()] = False,
) -> Response:
    try:
        payload = AllowlistEntryIn(value=value, note=note, mine=mine)
    except ValidationError as exc:
        return _allowlist_error(
            request, conn, _validation_message(exc), value=value, note=note, status_code=400
        )
    try:
        add_entry(conn, payload.value, payload.note, mine=payload.mine, now=utcnow())
    except ValueError as exc:
        return _allowlist_error(
            request, conn, str(exc), value=payload.value, note=payload.note, status_code=400
        )
    return RedirectResponse("/allowlist", status_code=303)


def _read_upload(file: UploadFile | None) -> bytes:
    """The uploaded list's bytes, read at most one byte past the size limit."""
    if file is None or not file.filename:
        raise ValueError("Choose a file to import.")
    return file.file.read(MAX_BYTES + 1)


@router.post("/allowlist/import", dependencies=[Depends(check_csrf)])
def import_allowlist_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    file: Annotated[UploadFile | None, File()] = None,
    mine: Annotated[bool, Form()] = False,
) -> Response:
    try:
        lines = parse_list_file(_read_upload(file))
    except ValueError as exc:
        return _allowlist_error(request, conn, str(exc), value="", note="", status_code=400)
    flash(request, summary(import_entries(conn, lines, mine=mine, now=utcnow())))
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


@router.post("/allowlist/mine", dependencies=[Depends(check_csrf)])
def set_mine_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    value: Annotated[str, Form()] = "",
    mine: Annotated[bool, Form()] = False,
) -> Response:
    """Flag an entry as your own network (or clear the flag)."""
    try:
        set_mine(conn, value, mine)
    except ValueError as exc:
        return _allowlist_error(request, conn, str(exc), value=value, note="", status_code=400)
    except NotFoundError as exc:
        return _allowlist_error(request, conn, str(exc), value=value, note="", status_code=404)
    return RedirectResponse("/allowlist", status_code=303)


@router.post("/allowlist/detect", dependencies=[Depends(check_csrf)])
def detect_mine_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    """Show this host's public addresses as candidates; never adds anything itself."""
    context = _allowlist_context(conn)
    context["candidates"] = home_detector(request)(
        existing=operator_entries(conn), extra_hosts=_request_hosts(request)
    )
    return render(request, "allowlist.html", context)


@router.post("/allowlist/detect-public", dependencies=[Depends(check_csrf)])
def detect_public_ip_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    """Ask api.ipify.org for the public IP: only ever on this explicit request."""
    context = _allowlist_context(conn)
    public, candidate = public_ip_candidate(
        public_ip_fetcher_factory(request)(), existing=operator_entries(conn)
    )
    context["candidates"] = [candidate] if candidate is not None else []
    context["public_ip_failed"] = public is None
    return render(request, "allowlist.html", context)


def _request_hosts(request: Request) -> list[str]:
    """The host this server was reached at, as a candidate (filtered like the rest)."""
    return [request.url.hostname] if request.url.hostname else []


def _apply_enabled_change(
    request: Request,
    conn: sqlite3.Connection,
    source_id: str,
    enabled: bool,
    *,
    acknowledge_restricted: bool,
) -> Response:
    """Shared body of the enable/disable handlers below.

    Without htmx: ``PolicyError``/``NotFoundError`` re-render the full Sources
    page with the message (400/404), success is the usual ``303`` to
    ``/sources``.

    With htmx (``HX-Request``) the answer is always the Source's row, status
    ``200``: htmx swaps only 2xx bodies by default, and a full page can't go
    inside a ``<tr>``. A refusal shows as an inline alert in the row's action
    cell (the row itself unchanged); an unknown Source gets a one-cell error row.
    """
    htmx = request.headers.get("HX-Request") == "true"
    try:
        source = store_set_enabled(
            conn, source_id, enabled, acknowledge_restricted=acknowledge_restricted
        )
    except NotFoundError as exc:
        if htmx:
            return render_fragment(
                request, "_source_row_missing.html", {"source_id": source_id, "error": str(exc)}
            )
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "error": str(exc)},
            status_code=404,
        )
    except PolicyError as exc:
        if htmx:
            return render_fragment(
                request,
                "_source_row.html",
                {"source": get_source(conn, source_id), "row_error": str(exc)},
            )
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "error": str(exc)},
            status_code=400,
        )
    _notify_sources_changed(request)
    if htmx:
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
    name: Annotated[str, Form()],
    url: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    id: Annotated[str, Form()] = "",
    role: Annotated[str, Form()] = "blocklist",
    format: Annotated[str, Form()] = "plain",
    category: Annotated[str, Form()] = "malicious",
    csv_column: Annotated[int, Form()] = 0,
    json_keys: Annotated[str, Form()] = "",
    business_use: Annotated[str, Form()] = "unknown",
) -> Response:
    keys = tuple(key.strip() for key in json_keys.split(",") if key.strip())
    try:
        payload = CustomSourceIn(
            id=id,
            name=name.strip(),
            url=url.strip(),
            role=role,
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
    refusal = web_file_url_error(payload.url, request.app.state.data_dir)
    if refusal is not None:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "custom_error": refusal},
            status_code=400,
        )
    source_id = payload.id or new_custom_id(conn, payload.name)
    if payload.id and _source_exists(conn, source_id):
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "custom_error": f"{source_id} is already taken"},
            status_code=400,
        )
    try:
        with transaction(conn):
            add_custom_source(
                conn,
                source_id=source_id,
                name=payload.name,
                url=payload.url,
                fmt=payload.format,
                kind=payload.kind,
                # A category only matters for blocklists; allowlist Sources file as infrastructure.
                category=payload.category if payload.role == "blocklist" else "infrastructure",
                csv_column=payload.csv_column,
                json_keys=payload.json_keys,
                business_use=payload.business_use,
                role=payload.role,
            )
            store_set_enabled(conn, source_id, True)
    except ValueError as exc:
        return render(
            request,
            "sources.html",
            {"sources": list_sources(conn), "custom_error": str(exc)},
            status_code=400,
        )
    _notify_sources_changed(request)
    list_name = "Allowlist" if payload.role == "allowlist" else "blocklist"
    flash(request, f"Added {payload.name} as a {list_name} Source. The next fetch downloads it.")
    return RedirectResponse("/sources", status_code=303)


def _source_exists(conn: sqlite3.Connection, source_id: str) -> bool:
    try:
        get_source(conn, source_id)
    except NotFoundError:
        return False
    return True


@router.get("/settings")
def settings_page(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    return render(request, "settings.html", {"settings": load_settings(conn)})


@router.get("/settings/export")
def export_settings(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
) -> Response:
    now = utcnow()
    filename = f"threatcull-config-{now:%Y-%m-%d}.yaml"
    return Response(
        dump_config(conn, now=now),
        media_type="application/yaml",
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/settings/import", dependencies=[Depends(check_csrf)])
def import_settings(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    user: Annotated[str, Depends(require_user)],
    file: Annotated[UploadFile | None, File()] = None,
) -> Response:
    data_dir = request.app.state.data_dir
    try:
        result = apply_config(
            conn,
            parse_config(_read_upload(file)),
            now=utcnow(),
            url_check=lambda url: web_file_url_error(url, data_dir),
        )
    except ValueError as exc:  # ConfigError, or no file chosen
        context = {"settings": load_settings(conn), "import_error": str(exc)}
        return render(request, "settings.html", context, status_code=400)
    _notify_sources_changed(request)
    return render(
        request, "settings.html", {"settings": load_settings(conn), "import_result": result}
    )
