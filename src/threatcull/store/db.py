# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite connection, schema migrations and transactions."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE sources (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        family TEXT NOT NULL,
        url TEXT NOT NULL,
        format TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('ip', 'domain')),
        role TEXT NOT NULL CHECK (role IN ('blocklist', 'allowlist')),
        category TEXT NOT NULL,
        licence_class TEXT NOT NULL,
        business_use TEXT NOT NULL,
        licence TEXT NOT NULL,
        licence_url TEXT NOT NULL,
        refresh_minutes INTEGER NOT NULL,
        csv_column INTEGER NOT NULL DEFAULT 0,
        json_keys TEXT NOT NULL DEFAULT '[]',
        custom INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 0,
        disabled_reason TEXT,
        etag TEXT,
        last_modified TEXT,
        last_success_at TEXT,
        last_attempt_at TEXT,
        last_error TEXT
    );
    CREATE TABLE indicators (
        id INTEGER PRIMARY KEY,
        value TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain'))
    );
    CREATE TABLE sightings (
        source_id TEXT NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
        indicator_id INTEGER NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        current INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (source_id, indicator_id)
    ) WITHOUT ROWID;
    CREATE INDEX sightings_indicator ON sightings (indicator_id);
    CREATE TABLE allowlist (
        id INTEGER PRIMARY KEY,
        value TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE outputs (
        name TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('ip', 'domain')),
        categories TEXT NOT NULL,
        min_tier TEXT NOT NULL CHECK (min_tier IN ('high', 'medium', 'low')),
        max_entries INTEGER,
        format TEXT NOT NULL,
        feed_token_hash TEXT NOT NULL,
        last_published_at TEXT,
        last_count INTEGER
    );
    CREATE TABLE runs (
        id INTEGER PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('fetch', 'compile')),
        source_id TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        counts TEXT NOT NULL DEFAULT '{}',
        error TEXT
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    PRAGMA user_version = 1;
    """,
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    PRAGMA user_version = 2;
    """,
    """
    CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL,
        username TEXT NOT NULL REFERENCES users (username) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        last_used_at TEXT
    );
    PRAGMA user_version = 3;
    """,
    """
    CREATE TABLE home_network (
        id INTEGER PRIMARY KEY,
        value TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
        note TEXT NOT NULL DEFAULT '',
        origin TEXT NOT NULL CHECK (origin IN ('manual', 'auto')),
        created_at TEXT NOT NULL
    );
    ALTER TABLE runs ADD COLUMN home_hits TEXT NOT NULL DEFAULT '[]';
    PRAGMA user_version = 4;
    """,
    """
    ALTER TABLE runs ADD COLUMN stats TEXT NOT NULL DEFAULT '{}';
    PRAGMA user_version = 5;
    """,
    """
    ALTER TABLE outputs ADD COLUMN last_sources TEXT;
    PRAGMA user_version = 6;
    """,
    # Business Mode was removed: drop its setting and the reason it left on Sources
    # (those Sources stay disabled until the operator enables them).
    """
    DELETE FROM settings WHERE key = 'business_mode';
    UPDATE sources SET disabled_reason = NULL
        WHERE disabled_reason = 'Disabled by Business Mode: not cleared for business use';
    PRAGMA user_version = 7;
    """,
    # The Home Network becomes Allowlist entries flagged "mine" (alert when a Source
    # lists them). An entry on both lists keeps its Allowlist note.
    """
    ALTER TABLE allowlist ADD COLUMN mine INTEGER NOT NULL DEFAULT 0;
    UPDATE allowlist SET mine = 1 WHERE value IN (SELECT value FROM home_network);
    INSERT INTO allowlist (value, kind, note, created_at, mine)
        SELECT value, kind, note, created_at, 1 FROM home_network
        WHERE value NOT IN (SELECT value FROM allowlist);
    DROP TABLE home_network;
    PRAGMA user_version = 8;
    """,
)

SCHEMA_VERSION = len(_MIGRATIONS)


def connect(path: Path | str) -> sqlite3.Connection:
    """Open (and migrate) the ThreatCull database in autocommit mode."""
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    current: int = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, script in enumerate(_MIGRATIONS, start=1):
        if version > current:
            conn.executescript(f"BEGIN;\n{script}\nCOMMIT;")


@contextmanager
def transaction(
    conn: sqlite3.Connection, *, begin: Literal["IMMEDIATE", "DEFERRED"] = "IMMEDIATE"
) -> Iterator[sqlite3.Connection]:
    """Run a block atomically; nested use joins the enclosing transaction.

    ``IMMEDIATE`` (the default) takes the write lock up front, so a
    read-then-write block never fails half-way on a lock upgrade. ``DEFERRED``
    takes locks only as each database is touched: a block that writes only
    TEMP tables then never locks the main database against other writers.
    """
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN DEFERRED" if begin == "DEFERRED" else "BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        # SQLite may already have rolled back (e.g. SQLITE_FULL); a second ROLLBACK
        # would raise and hide the original error.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
