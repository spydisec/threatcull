# SPDX-License-Identifier: AGPL-3.0-only
"""API tokens for scripts: bound to a web UI user, stored as SHA-256 only."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from threatcull.clock import ts
from threatcull.store.errors import NotFoundError

log = logging.getLogger(__name__)

TOKEN_PREFIX = "tc_"  # noqa: S105 - a public prefix, not a secret
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# last_used_at is informational: refresh it at most this often per token, so a
# busy script doesn't cost a database write on every request.
LAST_USED_RESOLUTION = timedelta(minutes=1)


@dataclass(frozen=True)
class ApiTokenInfo:
    """What ``list_api_tokens`` shows; never the hash."""

    name: str
    username: str
    created_at: str
    last_used_at: str | None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_api_token(conn: sqlite3.Connection, name: str, username: str, *, now: datetime) -> str:
    """Create a token for ``username``; returns the plaintext (shown once, never stored)."""
    if not _NAME.fullmatch(name):
        raise ValueError(
            f"API token name {name!r} must be 1-64 characters of A-Z, a-z, 0-9, '_', '.' or '-'"
        )
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is None:
        raise NotFoundError(f"no user {username!r}")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    try:
        conn.execute(
            "INSERT INTO api_tokens (name, token_hash, username, created_at) VALUES (?, ?, ?, ?)",
            (name, _hash(token), username, ts(now)),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"API token {name!r} already exists") from exc
    return token


def verify_api_token(conn: sqlite3.Connection, token: str, *, now: datetime) -> str | None:
    """The username ``token`` belongs to, or ``None``.

    Every stored hash is compared in constant time (no early exit). A token
    whose user no longer exists never verifies.
    """
    if not token.startswith(TOKEN_PREFIX):
        return None
    candidate = _hash(token).encode()
    rows = conn.execute(
        "SELECT t.id, t.token_hash, t.username, t.last_used_at FROM api_tokens AS t "
        "JOIN users AS u ON u.username = t.username"
    ).fetchall()
    match: sqlite3.Row | None = None
    for row in rows:
        if secrets.compare_digest(candidate, row["token_hash"].encode()):
            match = row
    if match is None:
        return None
    stamp = ts(now)
    last_used: str | None = match["last_used_at"]
    if last_used is None or last_used <= ts(now - LAST_USED_RESOLUTION):
        try:
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (stamp, match["id"])
            )
        except sqlite3.OperationalError:
            # Informational only: a busy database must not fail the request.
            log.debug(
                "last_used_at not recorded for row %s (database busy)", match["id"], exc_info=True
            )
    username: str = match["username"]
    return username


def revoke_api_token(conn: sqlite3.Connection, name: str) -> None:
    if conn.execute("DELETE FROM api_tokens WHERE name = ?", (name,)).rowcount == 0:
        raise NotFoundError(f"no API token {name!r}")


def list_api_tokens(conn: sqlite3.Connection) -> list[ApiTokenInfo]:
    rows = conn.execute(
        "SELECT name, username, created_at, last_used_at FROM api_tokens ORDER BY name"
    ).fetchall()
    return [
        ApiTokenInfo(
            name=row["name"],
            username=row["username"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )
        for row in rows
    ]
