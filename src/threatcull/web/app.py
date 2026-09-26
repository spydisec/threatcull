# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, Response

from threatcull.datadir import ensure_data_dir
from threatcull.home_detect import detect_candidates, public_ip_fetcher
from threatcull.store.users import warm_up as warm_up_password_checks
from threatcull.web.deps import DB_NAME, IMPORTS_DIR, open_db
from threatcull.web.jobs import PipelineRunner
from threatcull.web.routes import api, auth, feeds, health, pages
from threatcull.web.scheduler import Scheduler
from threatcull.web.security import (
    CsrfError,
    ForwardedHeadersMiddleware,
    LoginRateLimiter,
    LoginRequiredError,
    SecurityHeadersMiddleware,
    load_or_create_secret,
    login_required_response,
    parse_trusted_proxies,
    unhandled_exception_response,
)
from threatcull.web.templating import STATIC_DIR, render

__all__ = ["DB_NAME", "SESSION_COOKIE", "SESSION_MAX_AGE", "create_app", "open_db"]

SESSION_COOKIE = "threatcull_session"
SESSION_MAX_AGE = 12 * 60 * 60  # seconds
BUSY_RETRY_AFTER = 30  # seconds; a locked write already waited store.db.BUSY_TIMEOUT_S


async def _csrf_expired_response(request: Request, exc: Exception) -> Response:
    del exc  # nothing request-specific belongs in this page
    return render(request, "csrf_expired.html", status_code=403)


async def _database_busy_response(request: Request, exc: Exception) -> Response:
    """A write that waited out the busy timeout: 503 with a retry hint, not a 500."""
    if not isinstance(exc, sqlite3.OperationalError) or "locked" not in str(exc):
        return await unhandled_exception_response(request, exc)
    headers = {"Retry-After": str(BUSY_RETRY_AFTER)}
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            {"detail": "database busy; try again shortly"}, status_code=503, headers=headers
        )
    return render(request, "busy.html", status_code=503, headers=headers)


def _no_op() -> None:
    return None


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the built-in scheduler (if asked) for the app's lifetime."""
    scheduler: Scheduler | None = None
    if app.state.start_scheduler:
        scheduler = Scheduler(app.state.data_dir, app.state.runner)
        scheduler.start()
        app.state.scheduler = scheduler
        app.state.on_sources_changed = scheduler.rescan
    try:
        yield
    finally:
        if scheduler is not None:
            app.state.on_sources_changed = _no_op
            app.state.scheduler = None
            scheduler.shutdown()


def create_app(
    data_dir: Path,
    *,
    start_scheduler: bool = True,
    secure_cookies: bool = False,
    trusted_proxies: Iterable[str] = (),
) -> FastAPI:
    """Build the ThreatCull web application rooted at ``data_dir``.

    With ``start_scheduler`` the app's lifespan runs the built-in scheduler
    (periodic Fetches and Compiles); tests pass ``False`` to keep it off.
    ``secure_cookies`` sets the session cookie's ``Secure`` flag (HTTPS via a
    reverse proxy). ``trusted_proxies`` (IPs or CIDRs) are the peers whose
    ``X-Forwarded-For`` the login rate limiter believes; by default, none.
    """
    app = FastAPI(
        title="ThreatCull", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan
    )
    ensure_data_dir(data_dir)
    app.state.data_dir = data_dir
    # Where web-added file:// Sources read from (air-gap: drop feed files here).
    (data_dir / IMPORTS_DIR).mkdir(parents=True, exist_ok=True)
    app.state.start_scheduler = start_scheduler
    app.state.scheduler = None
    app.state.secret_key = load_or_create_secret(data_dir)
    app.state.trusted_proxies = parse_trusted_proxies(trusted_proxies)
    app.state.login_limiter = LoginRateLimiter()
    app.state.login_verify_slots = auth.new_verify_slots()
    # Called after any Source enable/disable, custom-Source add or Business
    # Mode change; the lifespan points it at the running scheduler's rescan.
    app.state.on_sources_changed = _no_op
    # One runner per app: "Run now", force Compile and the scheduler share its
    # lock, so only one pipeline run happens at a time.
    app.state.runner = PipelineRunner(data_dir)
    # The Allowlist "Detect" button reads local files only; the public-IP Fetcher is
    # built (and api.ipify.org contacted) only when an operator presses its button.
    app.state.home_detector = detect_candidates
    app.state.public_ip_fetcher_factory = public_ip_fetcher
    warm_up_password_checks()  # no first-login timing tell for unknown usernames
    # Covers the one response SecurityHeadersMiddleware can't reach: Starlette's
    # own fallback 500 for a truly unhandled exception (see security.py).
    app.add_exception_handler(Exception, unhandled_exception_response)
    app.add_exception_handler(LoginRequiredError, login_required_response)
    app.add_exception_handler(CsrfError, _csrf_expired_response)
    app.add_exception_handler(sqlite3.OperationalError, _database_busy_response)
    # Homelab first: plain HTTP on a bare IP works, so no Secure flag unless
    # `serve --secure-cookies` asks for it.
    app.add_middleware(
        SessionMiddleware,
        secret_key=app.state.secret_key.hex(),
        session_cookie=SESSION_COOKIE,
        max_age=SESSION_MAX_AGE,
        same_site="strict",
        https_only=secure_cookies,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    if app.state.trusted_proxies:
        # Outermost, so every route and middleware sees the proxy's scheme/host.
        app.add_middleware(ForwardedHeadersMiddleware, trusted=app.state.trusted_proxies)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(pages.router)
    app.include_router(api.router)
    app.include_router(feeds.router)
    return app
