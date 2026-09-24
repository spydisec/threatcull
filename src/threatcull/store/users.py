# SPDX-License-Identifier: AGPL-3.0-only
"""Web UI users: Argon2id password hashes, never plaintext."""

from __future__ import annotations

import functools
import hashlib
import re
import sqlite3
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from threatcull.clock import ts
from threatcull.store.errors import NotFoundError

MIN_PASSWORD_LENGTH = 12
_USERNAME = re.compile(r"[a-z0-9_.-]{3,32}")
_HASHER = PasswordHasher()  # argon2-cffi's default type is Argon2id


@functools.cache
def _dummy_hash() -> str:
    """A real hash of a throwaway password, verified when the username is unknown."""
    return _HASHER.hash("threatcull-timing-equaliser")


def warm_up() -> None:
    """Compute the dummy hash now (app start-up), not on the first unknown-user login."""
    _dummy_hash()


def _fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def password_fingerprint(conn: sqlite3.Connection, username: str) -> str | None:
    """A short digest of the user's current password hash; ``None`` if no such user.

    Sessions store it at login, so they stop working once the password
    changes or the user is deleted.
    """
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    return _fingerprint(row["password_hash"]) if row is not None else None


def _check_username(username: str) -> None:
    if not _USERNAME.fullmatch(username):
        raise ValueError(
            f"username {username!r} must be 3-32 characters of a-z, 0-9, '_', '.' or '-'"
        )


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def create_user(conn: sqlite3.Connection, username: str, password: str, *, now: datetime) -> None:
    _check_username(username)
    _check_password(password)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, _HASHER.hash(password), ts(now)),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"user {username!r} already exists") from exc


def verify_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    """True only for a known user with the right password.

    An unknown username still costs one Argon2 verify (against a dummy hash), so
    response time does not reveal which usernames exist.
    """
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    stored: str = row["password_hash"] if row is not None else _dummy_hash()
    try:
        _HASHER.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False
    if row is None:  # someone guessed the dummy password; still no such user
        return False
    if _HASHER.check_needs_rehash(stored):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (_HASHER.hash(password), username),
        )
    return True


def count_users(conn: sqlite3.Connection) -> int:
    count: int = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return count


def set_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    _check_password(password)
    cursor = conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (_HASHER.hash(password), username),
    )
    if cursor.rowcount == 0:
        raise NotFoundError(f"no user {username!r}")
