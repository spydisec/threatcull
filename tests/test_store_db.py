# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from pathlib import Path

import pytest

from threatcull.store import db
from threatcull.store.db import SCHEMA_VERSION, connect, migrate, transaction


def test_connect_creates_schema_in_wal_mode(conn: sqlite3.Connection) -> None:
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    expected = {"sources", "indicators", "sightings", "allowlist", "outputs", "runs", "settings"}
    assert tables >= expected
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_migrate_is_idempotent(conn: sqlite3.Connection) -> None:
    migrate(conn)
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_reopening_keeps_data(tmp_path: Path) -> None:
    first = connect(tmp_path / "db.sqlite")
    first.execute("INSERT INTO settings (key, value) VALUES ('k', '1')")
    first.close()
    second = connect(tmp_path / "db.sqlite")
    assert second.execute("SELECT value FROM settings WHERE key = 'k'").fetchone()[0] == "1"
    second.close()


def test_transaction_rolls_back_on_error(conn: sqlite3.Connection) -> None:
    with pytest.raises(RuntimeError), transaction(conn):  # noqa: PT012
        conn.execute("INSERT INTO settings (key, value) VALUES ('k', '1')")
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0


def test_original_error_survives_an_sqlite_auto_rollback(conn: sqlite3.Connection) -> None:
    with pytest.raises(RuntimeError, match="original"), transaction(conn):  # noqa: PT012
        conn.execute("ROLLBACK")  # what SQLite does itself on e.g. SQLITE_FULL
        raise RuntimeError("original")
    assert not conn.in_transaction


def test_nested_transaction_joins_outer(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        conn.execute("INSERT INTO settings (key, value) VALUES ('a', '1')")
        with transaction(conn):
            conn.execute("INSERT INTO settings (key, value) VALUES ('b', '2')")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 2


def test_migration_4_adds_home_network_to_a_version_3_database(tmp_path: Path) -> None:
    path = tmp_path / "v3.db"
    raw = sqlite3.connect(path, isolation_level=None)
    raw.executescript("BEGIN;\n" + "\n".join(db._MIGRATIONS[:3]) + "\nCOMMIT;")
    # A Run recorded before the upgrade: the new `home_hits` column must default in cleanly.
    raw.execute(
        "INSERT INTO runs (type, started_at, finished_at, status, counts) "
        "VALUES ('compile', '2026-01-01T00:00:00+00:00', '2026-01-01T00:01:00+00:00', "
        "'ok', '{}')"
    )
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 3
    raw.close()

    upgraded = db.connect(path)
    try:
        assert upgraded.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION >= 4
        columns = [r["name"] for r in upgraded.execute("PRAGMA table_info(home_network)")]
        assert columns == ["id", "value", "kind", "note", "origin", "created_at"]
        run = upgraded.execute("SELECT status, home_hits FROM runs").fetchone()
        assert (run["status"], run["home_hits"]) == ("ok", "[]")
    finally:
        upgraded.close()
