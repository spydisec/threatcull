# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
import threading
from pathlib import Path

import pytest

from threatcull.store import db
from threatcull.store.db import SCHEMA_VERSION, connect, migrate, transaction

_OLD_SOURCE = (
    "INSERT INTO sources (id, name, family, url, format, kind, role, category, "
    "licence_class, business_use, licence, licence_url, refresh_minutes, csv_column, "
    "json_keys, custom, enabled, disabled_reason) VALUES (?, 'Old', ?, 'https://x', "
    "'plain', 'ip', 'blocklist', 'malicious', 'restricted', 'forbidden', 'CC BY-NC', "
    "'https://x/l', 60, 0, '[]', 0, ?, ?)"
)


def _at_version(path: Path, version: int) -> sqlite3.Connection:
    """A database migrated only up to ``version``, as an older ThreatCull left it."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    for script in db._MIGRATIONS[:version]:
        conn.executescript(f"BEGIN;\n{script}\nCOMMIT;")
    return conn


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
        # Migration 4 created home_network; migration 8 merged it into the allowlist.
        tables = {r[0] for r in upgraded.execute("SELECT name FROM sqlite_master")}
        assert "home_network" not in tables
        assert "mine" in [r["name"] for r in upgraded.execute("PRAGMA table_info(allowlist)")]
        run = upgraded.execute("SELECT status, home_hits FROM runs").fetchone()
        assert (run["status"], run["home_hits"]) == ("ok", "[]")
    finally:
        upgraded.close()


def test_migration_drops_business_mode_and_its_disabled_reason(tmp_path: Path) -> None:
    conn = _at_version(tmp_path / "old.db", 6)
    conn.execute("INSERT INTO settings (key, value) VALUES ('business_mode', 'true')")
    conn.execute(
        _OLD_SOURCE,
        ("nc", "nc", 0, "Disabled by Business Mode: not cleared for business use"),
    )
    conn.executescript(db._MIGRATIONS[6])  # migration 7: Business Mode removed
    assert (
        conn.execute("SELECT COUNT(*) FROM settings WHERE key = 'business_mode'").fetchone()[0] == 0
    )
    row = conn.execute("SELECT enabled, disabled_reason FROM sources WHERE id = 'nc'").fetchone()
    conn.close()
    assert (row["enabled"], row["disabled_reason"]) == (0, None)


def test_migration_moves_home_network_entries_into_the_allowlist(tmp_path: Path) -> None:
    conn = _at_version(tmp_path / "old.db", 7)
    conn.executescript(
        "INSERT INTO home_network (value, kind, note, origin, created_at) VALUES "
        "('45.9.20.1', 'ip', 'office', 'manual', '2026-09-01T00:00:00+00:00'),"
        "('pay.example.com', 'domain', 'shop', 'auto', '2026-09-01T00:00:00+00:00');"
        "INSERT INTO allowlist (value, kind, note, created_at) VALUES "
        "('pay.example.com', 'domain', 'payments', '2026-09-01T00:00:00+00:00');"
    )
    migrate(conn)
    rows = conn.execute("SELECT value, note, mine FROM allowlist ORDER BY value").fetchall()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert [tuple(r) for r in rows] == [
        ("45.9.20.1", "office", 1),
        ("pay.example.com", "payments", 1),
    ]
    assert "home_network" not in tables


def test_migration_drops_licence_columns_and_keeps_the_sources(tmp_path: Path) -> None:
    conn = _at_version(tmp_path / "old.db", 8)
    conn.execute(
        _OLD_SOURCE,
        ("strict", "strict", 0, "Terms changed to restricted; acknowledge to re-enable"),
    )
    conn.execute(_OLD_SOURCE, ("kept", "kept", 1, None))
    migrate(conn)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(sources)")}
    rows = conn.execute("SELECT id, enabled, disabled_reason FROM sources ORDER BY id").fetchall()
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    assert not columns & {"licence", "licence_url", "licence_class", "business_use"}
    assert [tuple(r) for r in rows] == [("kept", 1, None), ("strict", 0, None)]
    assert version == SCHEMA_VERSION >= 9


def test_migration_10_adds_content_hash_columns(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(sources)")}
    assert {"content_sha256", "content_current"} <= columns


def test_temp_tables_live_on_disk(conn: sqlite3.Connection) -> None:
    # 1 = FILE: large TEMP tables must not depend on the SQLite build's default.
    assert conn.execute("PRAGMA temp_store").fetchone()[0] == 1


def test_migration_11_backfills_last_changed_at_from_the_newest_first_seen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "old.db"
    old = _at_version(path, 10)
    for source_id in ("busy", "empty"):
        old.execute(
            "INSERT INTO sources (id, name, family, url, format, kind, role, category, "
            "refresh_minutes) VALUES (?, ?, ?, 'https://x', 'plain', 'ip', 'blocklist', "
            "'malicious', 60)",
            (source_id, source_id, source_id),
        )
    old.execute("INSERT INTO indicators (id, value, kind) VALUES (1, '45.9.20.1', 'ip')")
    old.execute("INSERT INTO indicators (id, value, kind) VALUES (2, '45.9.20.2', 'ip')")
    old.execute(
        "INSERT INTO sightings (source_id, indicator_id, first_seen, last_seen, current) "
        "VALUES ('busy', 1, '2021-01-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 1), "
        "('busy', 2, '2021-10-06T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 0)"
    )
    old.close()
    upgraded = connect(path)
    try:
        rows = {r[0]: r[1] for r in upgraded.execute("SELECT id, last_changed_at FROM sources")}
    finally:
        upgraded.close()
    assert rows == {"busy": "2021-10-06T00:00:00+00:00", "empty": None}


def _open_raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(
        path, timeout=db.BUSY_TIMEOUT_S, isolation_level=None, check_same_thread=False
    )
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def test_processes_migrating_at_the_same_time_run_each_migration_once(tmp_path: Path) -> None:
    for attempt in range(5):
        path = tmp_path / f"race-{attempt}.db"
        _open_raw(path).close()  # create the file in WAL mode first
        conns = [_open_raw(path) for _ in range(4)]
        start = threading.Barrier(len(conns))
        errors: list[BaseException] = []

        def run(
            conn: sqlite3.Connection,
            start: threading.Barrier = start,
            errors: list[BaseException] = errors,
        ) -> None:
            start.wait()
            try:
                migrate(conn)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(c,)) for c in conns]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert conns[0].execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        for conn in conns:
            conn.close()


def test_a_failing_migration_leaves_the_previous_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "x.db"
    connect(path).close()
    broken = "CREATE TABLE half_done (x INTEGER);\nSELECT * FROM no_such_table;"
    monkeypatch.setattr(db, "_MIGRATIONS", (*db._MIGRATIONS, broken))
    conn = _open_raw(path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            migrate(conn)
        assert not conn.in_transaction
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert (
            conn.execute("SELECT name FROM sqlite_master WHERE name = 'half_done'").fetchone()
            is None
        )
    finally:
        conn.close()
