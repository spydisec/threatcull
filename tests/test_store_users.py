# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from argon2 import PasswordHasher

from threatcull.store import db, users
from threatcull.store.errors import NotFoundError
from threatcull.store.users import count_users, create_user, set_password, verify_user

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
PASSWORD = "correct horse battery"  # noqa: S105 - test-only credential


def test_create_user_stores_an_argon2id_hash_never_plaintext(conn: sqlite3.Connection) -> None:
    create_user(conn, "admin", PASSWORD, now=NOW)
    row = conn.execute("SELECT username, password_hash, created_at FROM users").fetchone()
    assert row["username"] == "admin"
    assert row["password_hash"].startswith("$argon2id$")
    assert PASSWORD not in row["password_hash"]
    assert row["created_at"] == "2026-09-24T12:00:00+00:00"
    assert count_users(conn) == 1


@pytest.mark.parametrize("username", ["ab", "Admin", "a" * 33, "bad name", "bad/name", ""])
def test_create_user_rejects_bad_usernames(conn: sqlite3.Connection, username: str) -> None:
    with pytest.raises(ValueError, match="username"):
        create_user(conn, username, PASSWORD, now=NOW)
    assert count_users(conn) == 0


@pytest.mark.parametrize("username", ["abc", "ops_team.1-x", "a" * 32])
def test_create_user_accepts_valid_usernames(conn: sqlite3.Connection, username: str) -> None:
    create_user(conn, username, PASSWORD, now=NOW)
    assert count_users(conn) == 1


def test_create_user_rejects_a_short_password(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="12 characters"):
        create_user(conn, "admin", "x" * 11, now=NOW)
    assert count_users(conn) == 0


def test_create_user_rejects_a_duplicate(conn: sqlite3.Connection) -> None:
    create_user(conn, "admin", PASSWORD, now=NOW)
    with pytest.raises(ValueError, match="already exists"):
        create_user(conn, "admin", "another long password", now=NOW)
    assert count_users(conn) == 1


def test_verify_user(conn: sqlite3.Connection) -> None:
    create_user(conn, "admin", PASSWORD, now=NOW)
    assert verify_user(conn, "admin", PASSWORD) is True
    assert verify_user(conn, "admin", "wrong password!!") is False
    assert verify_user(conn, "nobody", PASSWORD) is False
    assert verify_user(conn, "admin", "") is False


def test_verify_user_on_unknown_user_still_runs_a_hash_verify(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Unknown usernames must cost the same Argon2 verify as wrong passwords, so
    # response timing doesn't reveal which usernames exist.
    calls: list[str] = []

    class SpyHasher(PasswordHasher):
        def verify(self, hash: str | bytes, password: str | bytes) -> Literal[True]:
            calls.append(str(hash))
            return super().verify(hash, password)

    monkeypatch.setattr(users, "_HASHER", SpyHasher())
    assert verify_user(conn, "nobody", PASSWORD) is False
    assert len(calls) == 1
    assert calls[0].startswith("$argon2id$")


def test_set_password_replaces_the_hash(conn: sqlite3.Connection) -> None:
    create_user(conn, "admin", PASSWORD, now=NOW)
    set_password(conn, "admin", "a brand new password")
    assert verify_user(conn, "admin", "a brand new password") is True
    assert verify_user(conn, "admin", PASSWORD) is False


def test_set_password_validates_and_needs_an_existing_user(conn: sqlite3.Connection) -> None:
    create_user(conn, "admin", PASSWORD, now=NOW)
    with pytest.raises(ValueError, match="12 characters"):
        set_password(conn, "admin", "short")
    with pytest.raises(NotFoundError):
        set_password(conn, "nobody", "a brand new password")


def test_migration_2_adds_users_to_a_version_1_database(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    raw = sqlite3.connect(path, isolation_level=None)
    raw.executescript(f"BEGIN;\n{db._MIGRATIONS[0]}\nCOMMIT;")
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 1
    raw.close()

    upgraded = db.connect(path)
    try:
        assert upgraded.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION >= 2
        columns = [r["name"] for r in upgraded.execute("PRAGMA table_info(users)")]
        assert columns == ["id", "username", "password_hash", "created_at"]
    finally:
        upgraded.close()


def test_verify_user_rejects_the_dummy_password_for_an_unknown_user(
    conn: sqlite3.Connection,
) -> None:
    dummy = "threatcull-timing-equaliser"
    assert users._HASHER.verify(users._dummy_hash(), dummy)
    assert verify_user(conn, "nobody", dummy) is False


def test_verify_user_upgrades_an_outdated_hash(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(users, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8192))
    create_user(conn, "admin", PASSWORD, now=NOW)
    old = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    monkeypatch.undo()
    assert verify_user(conn, "admin", PASSWORD) is True
    new = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert new != old
    assert not users._HASHER.check_needs_rehash(new)
    assert verify_user(conn, "admin", PASSWORD) is True


def test_list_users_is_sorted_and_hash_free(conn: sqlite3.Connection) -> None:
    create_user(conn, "zed", PASSWORD, now=NOW)
    create_user(conn, "amy", PASSWORD, now=NOW)
    assert users.list_users(conn) == [
        ("amy", "2026-09-24T12:00:00+00:00"),
        ("zed", "2026-09-24T12:00:00+00:00"),
    ]
