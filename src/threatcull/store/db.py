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
    # 2.0 drops licence data: every Source is a feed the operator chooses to use.
    # Sources disabled because their terms turned restricted stay disabled, without
    # the reason that no longer applies.
    """
    ALTER TABLE sources DROP COLUMN licence_class;
    ALTER TABLE sources DROP COLUMN business_use;
    ALTER TABLE sources DROP COLUMN licence;
    ALTER TABLE sources DROP COLUMN licence_url;
    UPDATE sources SET disabled_reason = NULL
        WHERE disabled_reason = 'Terms changed to restricted; acknowledge to re-enable';
    PRAGMA user_version = 9;
    """,
    # 2.3: a Fetch whose download hashes the same as the last applied one skips
    # parsing; content_current guards against Sightings changed since (prune).
    """
    ALTER TABLE sources ADD COLUMN content_sha256 TEXT;
    ALTER TABLE sources ADD COLUMN content_current INTEGER;
    PRAGMA user_version = 10;
    """,
    # When each Source's list last gained or lost an Indicator (#84). The backfill
    # takes the newest first_seen: removals were never timed, so a Source can look
    # older than it is, never newer, until its next real change.
    """
    ALTER TABLE sources ADD COLUMN last_changed_at TEXT;
    UPDATE sources SET last_changed_at = (
        SELECT MAX(first_seen) FROM sightings WHERE sightings.source_id = sources.id
    );
    PRAGMA user_version = 11;
    """,
    # 2.8: Sightings stored compactly, and no longer rewritten by a Fetch that found the
    # list unchanged. Each Source gets a small integer key (``num``) that Sightings use
    # instead of repeating its text id, and times are whole seconds since 1970.
    # ``last_seen`` is NULL while the Source still lists the Indicator: such a Sighting
    # was last seen at the Source's ``last_success_at``, so a Fetch updates one row in
    # ``sources`` instead of every Sighting. Once the Indicator leaves the list,
    # ``last_seen`` holds the time of the last Fetch that still had it.
    """
    ALTER TABLE sources ADD COLUMN num INTEGER;
    UPDATE sources SET num = (SELECT COUNT(*) FROM sources AS other WHERE other.id <= sources.id);
    CREATE UNIQUE INDEX sources_num ON sources (num);
    CREATE TRIGGER sources_assign_num AFTER INSERT ON sources WHEN NEW.num IS NULL
    BEGIN
        UPDATE sources SET num = (SELECT COALESCE(MAX(num), 0) + 1 FROM sources)
        WHERE id = NEW.id;
    END;
    CREATE TABLE sightings_compact (
        source_num INTEGER NOT NULL REFERENCES sources (num) ON DELETE CASCADE,
        indicator_id INTEGER NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER,
        PRIMARY KEY (source_num, indicator_id)
    ) WITHOUT ROWID;
    INSERT INTO sightings_compact (source_num, indicator_id, first_seen, last_seen)
        SELECT s.num, g.indicator_id, CAST(strftime('%s', g.first_seen) AS INTEGER),
            CASE WHEN g.current = 1 THEN NULL
                 ELSE CAST(strftime('%s', g.last_seen) AS INTEGER) END
        FROM sightings AS g JOIN sources AS s ON s.id = g.source_id
        ORDER BY s.num, g.indicator_id;
    DROP TABLE sightings;
    ALTER TABLE sightings_compact RENAME TO sightings;
    CREATE INDEX sightings_indicator ON sightings (indicator_id);
    PRAGMA user_version = 12;
    """,
)

SCHEMA_VERSION = len(_MIGRATIONS)


# How long a write waits for another connection's write to finish. Saving a large
# Source (a million-entry domain list) holds the lock for several seconds.
BUSY_TIMEOUT_S = 30.0


def connect(path: Path | str) -> sqlite3.Connection:
    """Open (and migrate) the ThreatCull database in autocommit mode."""
    conn = sqlite3.connect(
        path, timeout=BUSY_TIMEOUT_S, isolation_level=None, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    # Temp tables (the Fetch staging table, the Compile's scored table) hold
    # millions of rows; keep them on disk whatever the SQLite build defaults to.
    conn.execute("PRAGMA temp_store = FILE")
    # 16 MiB of page cache (SQLite's default is 2 MiB). Index-heavy Fetches of a
    # million-line list ran about 20% faster in scripts/bench.py at no measurable
    # memory cost; larger caches cost RAM that small hosts don't have.
    conn.execute("PRAGMA cache_size = -16384")

    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Bring the schema to SCHEMA_VERSION, one migration per transaction.

    Each migration takes the write lock first (``BEGIN IMMEDIATE``) and reads
    ``user_version`` inside it, so a second process starting at the same moment
    (the server and a ``docker compose run`` CLI command after an upgrade) waits,
    then finds the migration done instead of running it again. The statements run
    one by one: ``executescript`` would commit the open transaction first.
    """
    for version, script in enumerate(_MIGRATIONS, start=1):
        if conn.execute("PRAGMA user_version").fetchone()[0] >= version:
            continue  # cheap check without the lock; repeated under it below
        with transaction(conn):
            if conn.execute("PRAGMA user_version").fetchone()[0] >= version:
                continue
            for statement in _statements(script):
                conn.execute(statement)


def _statements(script: str) -> Iterator[str]:
    """Split a migration script into complete SQL statements."""
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            if pending.strip():
                yield pending
            pending = ""
    if pending.strip():
        raise ValueError(f"incomplete SQL statement in a migration: {pending.strip()[:60]!r}")


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
