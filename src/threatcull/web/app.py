# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from threatcull.store.users import warm_up as warm_up_password_checks
from threatcull.web.deps import DB_NAME, open_db
from threatcull.web.routes import api, auth, feeds, health, pages
from threatcull.web.security import (
    CsrfError,
    LoginRateLimiter,
    LoginRequiredError,
    SecurityHeadersMiddleware,
    load_or_create_secret,
    login_required_response,
    unhandled_exception_response,
)
from threatcull.web.templating import STATIC_DIR, render

__all__ = ["DB_NAME", "SESSION_COOKIE", "SESSION_MAX_AGE", "create_app", "open_db"]

SESSION_COOKIE = "threatcull_session"
SESSION_MAX_AGE = 12 * 60 * 60  # seconds


async def _csrf_expired_response(request: Request, exc: Exception) -> Response:
    del exc  # nothing request-specific belongs in this page
    return render(request, "csrf_expired.html", status_code=403)


def create_app(data_dir: Path, *, start_scheduler: bool = True) -> FastAPI:
    """Build the ThreatCull web application rooted at ``data_dir``.

    ``start_scheduler`` is accepted for forward compatibility; scheduler
    wiring arrives in a later task.
    """
    app = FastAPI(title="ThreatCull", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.data_dir = data_dir
    app.state.start_scheduler = start_scheduler
    app.state.secret_key = load_or_create_secret(data_dir)
    app.state.login_limiter = LoginRateLimiter()
    app.state.login_verify_slots = auth.new_verify_slots()
    warm_up_password_checks()  # no first-login timing tell for unknown usernames
    # Covers the one response SecurityHeadersMiddleware can't reach: Starlette's
    # own fallback 500 for a truly unhandled exception (see security.py).
    app.add_exception_handler(Exception, unhandled_exception_response)
    app.add_exception_handler(LoginRequiredError, login_required_response)
    app.add_exception_handler(CsrfError, _csrf_expired_response)
    # Homelab first: plain HTTP on a bare IP works, so no Secure flag by default.
    app.add_middleware(
        SessionMiddleware,
        secret_key=app.state.secret_key.hex(),
        session_cookie=SESSION_COOKIE,
        max_age=SESSION_MAX_AGE,
        same_site="strict",
        https_only=False,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(pages.router)
    app.include_router(api.router)
    app.include_router(feeds.router)
    return app
