# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI dependencies shared across routes."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

from fastapi import HTTPException, Request

from threatcull.store.db import connect
from threatcull.web.security import (
    CSRF_FORM_FIELD,
    CSRF_HEADER,
    LoginRequiredError,
    csrf_token_matches,
)

DB_NAME = "threatcull.db"
SESSION_USER_KEY = "user"
_FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")


def open_db(data_dir: Path) -> sqlite3.Connection:
    """Open (and migrate) the database in ``data_dir``.

    Catalog sync and default Outputs are NOT done here: the CLI (``init``,
    ``serve``) does that once at start-up, not on every request.
    """
    return connect(data_dir / DB_NAME)


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """Open one database connection for this request, closed after the response."""
    conn = open_db(request.app.state.data_dir)
    try:
        yield conn
    finally:
        conn.close()


def session_user(request: Request) -> str | None:
    user = request.session.get(SESSION_USER_KEY)
    return user if isinstance(user, str) else None


def require_user(request: Request) -> str:
    """HTML pages: the logged-in username, or a ``303`` to ``/login``."""
    user = session_user(request)
    if user is None:
        raise LoginRequiredError
    return user


def require_api_user(request: Request) -> str:
    """``/api/`` routes: the logged-in username, or ``401`` JSON."""
    user = session_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


async def check_csrf(request: Request) -> None:
    """Every state-changing POST: ``403`` unless the session's CSRF token is sent.

    Accepted from the ``X-CSRF-Token`` header (API calls) or the ``csrf`` form
    field (HTML forms). Origin/Referer are deliberately never consulted.
    """
    submitted = request.headers.get(CSRF_HEADER)
    content_type = request.headers.get("content-type", "")
    if submitted is None and content_type.startswith(_FORM_TYPES):
        value = (await request.form()).get(CSRF_FORM_FIELD)
        submitted = value if isinstance(value, str) else None
    if not csrf_token_matches(request.session, submitted):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
