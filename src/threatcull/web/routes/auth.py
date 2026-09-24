# SPDX-License-Identifier: AGPL-3.0-only
"""Login, logout, and the first protected page and API route."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from starlette.responses import RedirectResponse, Response

from threatcull.store.users import verify_user
from threatcull.web.deps import (
    SESSION_USER_KEY,
    check_csrf,
    get_conn,
    require_api_user,
    require_user,
)
from threatcull.web.security import LoginRateLimiter, client_ip, rotate_csrf_token
from threatcull.web.templating import render

router = APIRouter()

LOGIN_FAILED = "Wrong username or password."
LOGIN_BLOCKED = "Too many failed logins. Wait a few minutes, then try again."


@router.get("/login")
def login_page(request: Request) -> Response:
    return render(request, "login.html", {"error": None, "username": ""})


@router.post("/login", dependencies=[Depends(check_csrf)])
def login(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> Response:
    limiter: LoginRateLimiter = request.app.state.login_limiter
    ip = client_ip(request)
    if limiter.is_blocked(ip):
        return render(
            request,
            "login.html",
            {"error": LOGIN_BLOCKED, "username": username},
            status_code=429,
            headers={"Retry-After": str(int(limiter.window_seconds))},
        )
    if not verify_user(conn, username, password):
        limiter.record_failure(ip)
        return render(
            request, "login.html", {"error": LOGIN_FAILED, "username": username}, status_code=401
        )
    limiter.reset(ip)
    request.session.clear()
    request.session[SESSION_USER_KEY] = username
    rotate_csrf_token(request.session)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(check_csrf)])
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/")
def home(request: Request, user: Annotated[str, Depends(require_user)]) -> Response:
    # Placeholder until the dashboard (Task 4) replaces it.
    return render(request, "base.html")


@router.get("/api/v1/me")
def me(user: Annotated[str, Depends(require_api_user)]) -> dict[str, str]:
    return {"username": user}
