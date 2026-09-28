# SPDX-License-Identifier: AGPL-3.0-only
"""Login and logout."""

from __future__ import annotations

import math
import sqlite3
import threading
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from starlette.responses import RedirectResponse, Response

from threatcull.store.users import password_fingerprint, verify_user
from threatcull.web.deps import SESSION_FINGERPRINT_KEY, SESSION_USER_KEY, check_csrf, get_conn
from threatcull.web.security import LoginRateLimiter, client_ip, rotate_csrf_token
from threatcull.web.templating import render

router = APIRouter()

LOGIN_FAILED = "Wrong username or password."
LOGIN_BLOCKED = "Too many failed logins. Wait a few minutes, then try again."
LOGIN_BUSY = "Too many login attempts, try again shortly."

# Each Argon2 verify takes ~64 MiB and real CPU time: cap how many run at once
# process-wide, and wait only briefly for a free slot.
MAX_CONCURRENT_VERIFIES = 4
VERIFY_WAIT_SECONDS = 2.0


def new_verify_slots() -> threading.BoundedSemaphore:
    return threading.BoundedSemaphore(MAX_CONCURRENT_VERIFIES)


@router.get("/login")
def login_page(request: Request) -> Response:
    return render(request, "login.html", {"error": None, "username": ""})


def _login_refused(request: Request, message: str, username: str, retry_after: int) -> Response:
    return render(
        request,
        "login.html",
        {"error": message, "username": username},
        status_code=429,
        headers={"Retry-After": str(retry_after)},
    )


@router.post("/login", dependencies=[Depends(check_csrf)])
def login(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",  # empty default for a form field, not a credential
) -> Response:
    limiter: LoginRateLimiter = request.app.state.login_limiter
    slots: threading.BoundedSemaphore = request.app.state.login_verify_slots
    ip = client_ip(request)
    # Reserve the attempt before verifying, so parallel requests can't overrun the limit.
    if not limiter.try_begin(ip):
        return _login_refused(request, LOGIN_BLOCKED, username, int(limiter.window_seconds))
    if not slots.acquire(timeout=VERIFY_WAIT_SECONDS):
        return _login_refused(request, LOGIN_BUSY, username, math.ceil(VERIFY_WAIT_SECONDS))
    try:
        ok = verify_user(conn, username, password)
        fingerprint = password_fingerprint(conn, username) if ok else None
    finally:
        slots.release()
    if fingerprint is None:
        return render(
            request, "login.html", {"error": LOGIN_FAILED, "username": username}, status_code=401
        )
    limiter.succeeded(ip)
    request.session.clear()
    request.session[SESSION_USER_KEY] = username
    request.session[SESSION_FINGERPRINT_KEY] = fingerprint
    rotate_csrf_token(request.session)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(check_csrf)])
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
