# SPDX-License-Identifier: AGPL-3.0-only
"""Allowlist entries: operator-supplied and Built-in (from allowlist Sources)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from threatcull.clock import ts
from threatcull.indicators import Indicator, IndicatorKind, normalize
from threatcull.listfile import ImportReport, ListLine, apply_lines
from threatcull.store.db import transaction
from threatcull.store.errors import NotFoundError


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    value: str
    kind: IndicatorKind
    note: str
    origin: str


def normalize_allow_value(raw: str) -> Indicator:
    indicator = normalize(raw, "ip") or normalize(raw, "domain")
    if indicator is None:
        raise ValueError(f"{raw.strip()!r} is not a public IP, CIDR or domain")
    return indicator


def add_entry(
    conn: sqlite3.Connection, raw: str, note: str = "", *, now: datetime
) -> AllowlistEntry:
    indicator = normalize_allow_value(raw)
    conn.execute(
        "INSERT INTO allowlist (value, kind, note, created_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (value) DO UPDATE SET note = excluded.note",
        (indicator.value, indicator.kind, note, ts(now)),
    )
    return AllowlistEntry(indicator.value, indicator.kind, note, "operator")


def import_entries(
    conn: sqlite3.Connection, lines: list[ListLine], *, now: datetime
) -> ImportReport:
    """Add every new value from an uploaded list in one transaction."""
    with transaction(conn):
        return apply_lines(
            lines,
            normalize=normalize_allow_value,
            existing={entry.value for entry in operator_entries(conn)},
            insert=lambda raw, note: add_entry(conn, raw, note, now=now),
        )


def remove_entry(conn: sqlite3.Connection, raw: str) -> None:
    value = normalize_allow_value(raw).value
    if conn.execute("DELETE FROM allowlist WHERE value = ?", (value,)).rowcount == 0:
        raise NotFoundError(f"{value} is not on the Allowlist")


def operator_entries(conn: sqlite3.Connection) -> list[AllowlistEntry]:
    rows = conn.execute("SELECT value, kind, note FROM allowlist ORDER BY value")
    return [AllowlistEntry(r["value"], r["kind"], r["note"], "operator") for r in rows]


def builtin_entries(conn: sqlite3.Connection) -> list[AllowlistEntry]:
    rows = conn.execute(
        """
        SELECT i.value, i.kind, s.id, s.name FROM sightings sg
        JOIN sources s ON s.id = sg.source_id
        JOIN indicators i ON i.id = sg.indicator_id
        WHERE s.role = 'allowlist' AND s.enabled = 1 AND sg.current = 1
        ORDER BY i.value
        """
    )
    return [
        AllowlistEntry(r["value"], r["kind"], f"Built-in Allowlist: {r['name']}", r["id"])
        for r in rows
    ]
