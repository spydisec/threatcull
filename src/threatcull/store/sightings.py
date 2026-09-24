# SPDX-License-Identifier: AGPL-3.0-only
"""Sightings: which Source listed which Indicator, and when."""

from __future__ import annotations

import sqlite3
from collections.abc import Collection
from datetime import datetime, timedelta

from threatcull.clock import ts
from threatcull.indicators import Indicator
from threatcull.store.db import transaction


def record_fetch_success(
    conn: sqlite3.Connection,
    source_id: str,
    indicators: Collection[Indicator],
    *,
    now: datetime,
    etag: str | None,
    last_modified: str | None,
) -> tuple[int, int]:
    """Make ``indicators`` the Source's current Sightings. Returns (added, removed)."""
    stamp = ts(now)
    with transaction(conn):
        conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS fetched (value TEXT PRIMARY KEY, kind TEXT NOT NULL)"
        )
        conn.execute("DELETE FROM fetched")
        conn.executemany(
            "INSERT OR IGNORE INTO fetched (value, kind) VALUES (?, ?)",
            ((indicator.value, indicator.kind) for indicator in indicators),
        )
        conn.execute(
            "INSERT OR IGNORE INTO indicators (value, kind) SELECT value, kind FROM fetched"
        )
        added: int = conn.execute(
            """
            SELECT COUNT(*) FROM fetched f
            JOIN indicators i ON i.value = f.value
            LEFT JOIN sightings s ON s.source_id = ? AND s.indicator_id = i.id
            WHERE s.indicator_id IS NULL OR s.current = 0
            """,
            (source_id,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO sightings (source_id, indicator_id, first_seen, last_seen, current)
            SELECT ?, i.id, ?, ?, 1 FROM fetched f JOIN indicators i ON i.value = f.value WHERE true
            ON CONFLICT (source_id, indicator_id)
            DO UPDATE SET last_seen = excluded.last_seen, current = 1
            """,
            (source_id, stamp, stamp),
        )
        removed = conn.execute(
            """
            UPDATE sightings SET current = 0
            WHERE source_id = ? AND current = 1 AND indicator_id NOT IN (
                SELECT i.id FROM fetched f JOIN indicators i ON i.value = f.value
            )
            """,
            (source_id,),
        ).rowcount
        conn.execute(
            """
            UPDATE sources SET etag = ?, last_modified = ?, last_success_at = ?,
                last_attempt_at = ?, last_error = NULL
            WHERE id = ?
            """,
            (etag, last_modified, stamp, stamp, source_id),
        )
    return added, removed


def record_not_modified(conn: sqlite3.Connection, source_id: str, *, now: datetime) -> None:
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
