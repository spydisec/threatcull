# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import sqlite3
from datetime import datetime, timedelta

import pytest

from threatcull.store.api_tokens import (
    TOKEN_PREFIX,
    create_api_token,
    list_api_tokens,
    revoke_api_token,
    verify_api_token,
)
from threatcull.store.errors import NotFoundError
from threatcull.store.users import create_user

PASSWORD = "correct horse battery"  # noqa: S105 - test-only credential


@pytest.fixture
def admin(conn: sqlite3.Connection, now: datetime) -> str:
    create_user(conn, "admin", PASSWORD, now=now)
    return "admin"


def test_token_is_prefixed_and_only_its_sha256_is_stored(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    token = create_api_token(conn, "backup-script", admin, now=now)
    assert token.startswith(TOKEN_PREFIX)
    assert len(token) > len(TOKEN_PREFIX) + 40
    row = conn.execute("SELECT * FROM api_tokens").fetchone()
    assert row["name"] == "backup-script"
    assert row["username"] == admin
    assert row["created_at"] == "2026-09-24T12:00:00+00:00"
    assert row["last_used_at"] is None
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in tuple(row)


def test_each_token_is_different(conn: sqlite3.Connection, now: datetime, admin: str) -> None:
    assert create_api_token(conn, "a", admin, now=now) != create_api_token(
        conn, "b", admin, now=now
    )


def test_verify_returns_the_bound_user(conn: sqlite3.Connection, now: datetime, admin: str) -> None:
    token = create_api_token(conn, "script", admin, now=now)
    assert verify_api_token(conn, token, now=now) == admin


@pytest.mark.parametrize("bad", ["", "tc_", "tc_nope", "not-a-token", "x" * 500])
def test_verify_rejects_unknown_tokens(
    conn: sqlite3.Connection, now: datetime, admin: str, bad: str
) -> None:
    create_api_token(conn, "script", admin, now=now)
    assert verify_api_token(conn, bad, now=now) is None


def test_verify_rejects_the_stored_hash_itself(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    create_api_token(conn, "script", admin, now=now)
    stored = conn.execute("SELECT token_hash FROM api_tokens").fetchone()[0]
    assert verify_api_token(conn, stored, now=now) is None


def test_token_stops_working_once_its_user_is_deleted(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    token = create_api_token(conn, "script", admin, now=now)
    conn.execute("DELETE FROM users WHERE username = ?", (admin,))
    assert verify_api_token(conn, token, now=now) is None


def test_revoked_token_no_longer_verifies(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    token = create_api_token(conn, "script", admin, now=now)
    revoke_api_token(conn, "script")
    assert verify_api_token(conn, token, now=now) is None
    assert list_api_tokens(conn) == []


def test_revoking_an_unknown_token_is_not_found(conn: sqlite3.Connection) -> None:
    with pytest.raises(NotFoundError):
        revoke_api_token(conn, "nope")


def test_create_needs_an_existing_user(conn: sqlite3.Connection, now: datetime) -> None:
    with pytest.raises(NotFoundError):
        create_api_token(conn, "script", "ghost", now=now)


def test_create_rejects_a_duplicate_name(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    create_api_token(conn, "script", admin, now=now)
    with pytest.raises(ValueError, match="already exists"):
        create_api_token(conn, "script", admin, now=now)


@pytest.mark.parametrize("name", ["", "has space", "a" * 65, "bad/name"])
def test_create_rejects_bad_names(
    conn: sqlite3.Connection, now: datetime, admin: str, name: str
) -> None:
    with pytest.raises(ValueError, match="name"):
        create_api_token(conn, name, admin, now=now)


def test_last_used_is_written_at_most_once_a_minute(
    conn: sqlite3.Connection, now: datetime, admin: str
) -> None:
    token = create_api_token(conn, "script", admin, now=now)

    def last_used() -> str | None:
        value: str | None = conn.execute("SELECT last_used_at FROM api_tokens").fetchone()[0]
        return value

    assert verify_api_token(conn, token, now=now) == admin
    assert last_used() == "2026-09-24T12:00:00+00:00"
    assert verify_api_token(conn, token, now=now + timedelta(seconds=59)) == admin
    assert last_used() == "2026-09-24T12:00:00+00:00"
    assert verify_api_token(conn, token, now=now + timedelta(seconds=60)) == admin
    assert last_used() == "2026-09-24T12:01:00+00:00"


def test_list_never_returns_hashes(conn: sqlite3.Connection, now: datetime, admin: str) -> None:
    token = create_api_token(conn, "script", admin, now=now)
    verify_api_token(conn, token, now=now)
    [info] = list_api_tokens(conn)
    assert info.name == "script"
    assert info.username == admin
    assert info.created_at == "2026-09-24T12:00:00+00:00"
    assert info.last_used_at == "2026-09-24T12:00:00+00:00"
    assert not hasattr(info, "token_hash")
    stored = conn.execute("SELECT token_hash FROM api_tokens").fetchone()[0]
    assert stored not in repr(info)
