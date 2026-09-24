# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI dependencies shared across routes."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from threatcull.store.db import connect
from threatcull.store.users import password_fingerprint
from threatcull.web.security import (
    CSRF_FORM_FIELD,
    CSRF_HEADER,
    CsrfError,
    LoginRequiredError,
    csrf_token_matches,
)

log = logging.getLogger(__name__)

DB_NAME = "threatcull.db"
SESSION_USER_KEY = "user"
SESSION_FINGERPRINT_KEY = "pwfp"
_FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")


def open_db(data_dir: Path) -> sqlite3.Connection:
    """Open (and migrate) the database in ``data_dir``.

    Catalog sync and default Outputs are NOT done here: the CLI (``init``,
    ``serve``) does that once at start-up, not on every request.
    """
    return connect(data_dir / DB_NAME)


def notify_sources_changed(request: Request) -> None:
    """Call the app's ``on_sources_changed`` hook (the scheduler's rescan).

    The Source change is already committed when this runs, so a failing
    rescan is logged, never turned into an error response.
    """
    on_changed = getattr(request.app.state, "on_sources_changed", None)
    if on_changed is None:
        return
    try:
        on_changed()
    except Exception:
        log.exception("rescan after a Source change failed")


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """Open one database connection for this request, closed after the response."""
    conn = open_db(request.app.state.data_dir)
    try:
        yield conn
    finally:
        conn.close()


def session_user(request: Request) -> str | None:
    """The username the session claims (not re-checked; for display only)."""
    user = request.session.get(SESSION_USER_KEY)
    return user if isinstance(user, str) else None


def _current_user(request: Request, conn: sqlite3.Connection) -> str | None:
    """The session's user, if it still exists with the password it logged in with.

    A session whose user was deleted, or whose password changed since login,
    is cleared.
    """
    user = session_user(request)
    if user is None:
        return None
    expected = password_fingerprint(conn, user)
    held = request.session.get(SESSION_FINGERPRINT_KEY)
    if expected is None or not isinstance(held, str) or not compare_digest(expected, held):
        request.session.clear()
        return None
    return user


def require_user(request: Request, conn: Annotated[sqlite3.Connection, Depends(get_conn)]) -> str:
    """HTML pages: the logged-in username, or a ``303`` to ``/login``."""
    user = _current_user(request, conn)
    if user is None:
        raise LoginRequiredError
    return user


def require_api_user(
    request: Request, conn: Annotated[sqlite3.Connection, Depends(get_conn)]
) -> str:
    """``/api/`` routes: the logged-in username, or ``401`` JSON."""
    user = _current_user(request, conn)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


async def check_csrf(request: Request) -> None:
    """Every state-changing POST: ``403`` unless the session's CSRF token is sent.

    Accepted from the ``X-CSRF-Token`` header (API calls) or the ``csrf`` form
    field (HTML forms). Origin/Referer are deliberately never consulted. An
    ``/api/`` request that fails gets JSON (``HTTPException``); any other
    request gets a rendered HTML page (``CsrfError``, handled in ``app.py``) —
    a form opened in another session shouldn't show the raw API error body.
    """
    submitted = request.headers.get(CSRF_HEADER)
    content_type = request.headers.get("content-type", "")
    if submitted is None and content_type.startswith(_FORM_TYPES):
        value = (await request.form()).get(CSRF_FORM_FIELD)
        submitted = value if isinstance(value, str) else None
    if csrf_token_matches(request.session, submitted):
        return
    if request.url.path.startswith("/api/"):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    raise CsrfError
