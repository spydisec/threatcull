# SPDX-License-Identifier: AGPL-3.0-only
"""Sightings: which Source listed which Indicator, and when."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta

from threatcull.clock import ts
from threatcull.indicators import Indicator
from threatcull.store.db import transaction


def stage_fetched(conn: sqlite3.Connection, indicators: Iterable[Indicator]) -> int:
    """Stream ``indicators`` into the TEMP table ``fetched``; returns how many distinct ones.

    Staging never touches Sightings: ``apply_fetched`` does that, so a Fetch that
    stages nothing valid can be dropped without harming the Source's current list.

    ``indicators`` is usually a lazy parse of a download, so this can take a
    while. The transaction is DEFERRED and writes only the TEMP database, so
    the main database's write lock is not held meanwhile: an operator's save
    on another connection goes through (only ``apply_fetched`` locks it).
    """
    with transaction(conn, begin="DEFERRED"):
        conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS fetched (value TEXT PRIMARY KEY, kind TEXT NOT NULL)"
        )
        conn.execute("DELETE FROM fetched")
        conn.executemany(
            "INSERT OR IGNORE INTO fetched (value, kind) VALUES (?, ?)",
            ((indicator.value, indicator.kind) for indicator in indicators),
        )
        staged: int = conn.execute("SELECT COUNT(*) FROM fetched").fetchone()[0]
    return staged


def apply_fetched(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    now: datetime,
    etag: str | None,
    last_modified: str | None,
    content_sha256: str | None = None,
) -> tuple[int, int]:
    """Make the staged Indicators the Source's current Sightings. Returns (added, removed).

    ``content_sha256`` is the digest of the download these Indicators came from,
    stored with the resulting current count for :func:`same_content`. Leaving
    it out clears any stored digest, so the next Fetch parses in full.
    """
    stamp = ts(now)
    with transaction(conn):
        conn.execute(
            "INSERT OR IGNORE INTO indicators (value, kind) SELECT value, kind FROM fetched"
        )
        # Look each staged value up in indicators once; the steps below then work on
        # integer ids instead of repeating the text join (3x faster on large lists).
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS fetched_ids (id INTEGER PRIMARY KEY)")
        conn.execute("DELETE FROM fetched_ids")
        conn.execute(
            "INSERT INTO fetched_ids (id) "
            "SELECT i.id FROM fetched f JOIN indicators i ON i.value = f.value"
        )
        added: int = conn.execute(
            """
            SELECT COUNT(*) FROM fetched_ids f
            LEFT JOIN sightings s ON s.source_id = ? AND s.indicator_id = f.id
            WHERE s.indicator_id IS NULL OR s.current = 0
            """,
            (source_id,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO sightings (source_id, indicator_id, first_seen, last_seen, current)
            SELECT ?, id, ?, ?, 1 FROM fetched_ids WHERE true
            ON CONFLICT (source_id, indicator_id)
            DO UPDATE SET last_seen = excluded.last_seen, current = 1
            """,
            (source_id, stamp, stamp),
        )
        removed = conn.execute(
            """
            UPDATE sightings SET current = 0
            WHERE source_id = ? AND current = 1
            AND indicator_id NOT IN (SELECT id FROM fetched_ids)
            """,
            (source_id,),
        ).rowcount
        conn.execute(
            """
            UPDATE sources SET etag = ?, last_modified = ?, last_success_at = ?,
                last_attempt_at = ?, last_error = NULL, content_sha256 = ?,
                content_current = (
                    SELECT COUNT(*) FROM sightings WHERE source_id = ? AND current = 1
                )
            WHERE id = ?
            """,
            (etag, last_modified, stamp, stamp, content_sha256, source_id, source_id),
        )
        conn.execute("DELETE FROM fetched")
        conn.execute("DELETE FROM fetched_ids")
    return added, removed


def sightings_unchanged(conn: sqlite3.Connection, source_id: str) -> bool:
    """True when the Source still has the current Sightings its last apply left.

    False after a prune removed some (a Source disabled past the retention
    period), or when no apply has recorded a count yet (lists applied before
    2.3). The Fetch then asks for the full list instead of trusting a 304 or
    an unchanged hash.
    """
    row = conn.execute(
        "SELECT content_current, "
        "(SELECT COUNT(*) FROM sightings WHERE source_id = ? AND current = 1) AS current_count "
        "FROM sources WHERE id = ?",
        (source_id, source_id),
    ).fetchone()
    return row is not None and row["content_current"] == row["current_count"]


def same_content(conn: sqlite3.Connection, source_id: str, content_sha256: str) -> bool:
    """True when ``content_sha256`` matches the download last applied for the Source.

    The Source's current Sightings must also still number what that apply left
    (:func:`sightings_unchanged`), so Sightings pruned since force a full parse.
    """
    row = conn.execute("SELECT content_sha256 FROM sources WHERE id = ?", (source_id,)).fetchone()
    if row is None or row["content_sha256"] != content_sha256:
        return False
    return sightings_unchanged(conn, source_id)


def record_fetch_success(
    conn: sqlite3.Connection,
    source_id: str,
    indicators: Iterable[Indicator],
    *,
    now: datetime,
    etag: str | None,
    last_modified: str | None,
) -> tuple[int, int]:
    """Make ``indicators`` the Source's current Sightings. Returns (added, removed)."""
    with transaction(conn):
        stage_fetched(conn, indicators)
        return apply_fetched(conn, source_id, now=now, etag=etag, last_modified=last_modified)


def record_not_modified(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    now: datetime,
    validators: tuple[str | None, str | None] | None = None,
) -> None:
    """Refresh the Source's current Sightings without changing them.

    ``validators`` is a new (ETag, Last-Modified) pair to store: a download whose
    content was unchanged still carries the server's latest validators.
    """
    stamp = ts(now)
    with transaction(conn):
        conn.execute(
            "UPDATE sightings SET last_seen = ? WHERE source_id = ? AND current = 1",
            (stamp, source_id),
        )
        conn.execute(
            "UPDATE sources SET last_success_at = ?, last_attempt_at = ?, last_error = NULL "
            "WHERE id = ?",
            (stamp, stamp, source_id),
        )
        if validators is not None:
            conn.execute(
                "UPDATE sources SET etag = ?, last_modified = ? WHERE id = ?",
                (*validators, source_id),
            )


def record_fetch_failure(
    conn: sqlite3.Connection, source_id: str, error: str, *, now: datetime
) -> None:
    conn.execute(
        "UPDATE sources SET last_attempt_at = ?, last_error = ? WHERE id = ?",
        (ts(now), error, source_id),
    )


def prune(conn: sqlite3.Connection, *, now: datetime, retention_days: int) -> int:
    """Delete Sightings older than the retention period and Indicators nobody lists."""
    cutoff = ts(now - timedelta(days=retention_days))
    with transaction(conn):
        deleted = conn.execute("DELETE FROM sightings WHERE last_seen < ?", (cutoff,)).rowcount
        conn.execute(
            "DELETE FROM indicators WHERE NOT EXISTS "
            "(SELECT 1 FROM sightings s WHERE s.indicator_id = indicators.id)"
        )
    return deleted
