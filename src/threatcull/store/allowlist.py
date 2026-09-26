# SPDX-License-Identifier: AGPL-3.0-only
"""Allowlist entries: operator-supplied and Built-in (from allowlist Sources).

An operator entry flagged ``mine`` is the operator's own network: it stays out of every
Output like any entry, and a Compile also reports when an upstream Source lists it.
"""

from __future__ import annotations

import ipaddress
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
    mine: bool = False


MINE_ORIGIN = "mine"
PRIVATE_MESSAGE = (
    "private and special-purpose addresses are never published; no allowlist entry is needed"
)


def normalize_allow_value(raw: str) -> Indicator:
    indicator = normalize(raw, "ip") or normalize(raw, "domain")
    if indicator is None:
        if _is_private(raw.strip()):
            raise ValueError(f"{raw.strip()!r}: {PRIVATE_MESSAGE}")
        raise ValueError(f"{raw.strip()!r} is not a public IP, CIDR or domain")
    return indicator


def _is_private(text: str) -> bool:
    try:
        return not ipaddress.ip_network(text, strict=False).is_global
    except ValueError:
        return False


def add_entry(
    conn: sqlite3.Connection, raw: str, note: str = "", *, mine: bool = False, now: datetime
) -> AllowlistEntry:
    indicator = normalize_allow_value(raw)
    conn.execute(
        "INSERT INTO allowlist (value, kind, note, created_at, mine) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (value) DO UPDATE SET note = excluded.note, mine = excluded.mine",
        (indicator.value, indicator.kind, note, ts(now), int(mine)),
    )
    return AllowlistEntry(indicator.value, indicator.kind, note, "operator", mine)


def set_mine(conn: sqlite3.Connection, raw: str, mine: bool) -> None:
    """Flag (or unflag) an existing entry as the operator's own network."""
    value = normalize_allow_value(raw).value
    if (
        conn.execute("UPDATE allowlist SET mine = ? WHERE value = ?", (int(mine), value)).rowcount
        == 0
    ):
        raise NotFoundError(f"{value} is not on the Allowlist")


def import_entries(
    conn: sqlite3.Connection, lines: list[ListLine], *, mine: bool = False, now: datetime
) -> ImportReport:
    """Add every new value from an uploaded list in one transaction (values already on
    the Allowlist keep their note and flag)."""
    with transaction(conn):
        return apply_lines(
            lines,
            normalize=normalize_allow_value,
            existing={entry.value for entry in operator_entries(conn)},
            insert=lambda raw, note: add_entry(conn, raw, note, mine=mine, now=now),
        )


def remove_entry(conn: sqlite3.Connection, raw: str) -> None:
    value = normalize_allow_value(raw).value
    if conn.execute("DELETE FROM allowlist WHERE value = ?", (value,)).rowcount == 0:
        raise NotFoundError(f"{value} is not on the Allowlist")


def operator_entries(conn: sqlite3.Connection) -> list[AllowlistEntry]:
    rows = conn.execute("SELECT value, kind, note, mine FROM allowlist ORDER BY value")
    return [
        AllowlistEntry(r["value"], r["kind"], r["note"], "operator", bool(r["mine"])) for r in rows
    ]


def mine_entries(conn: sqlite3.Connection) -> list[AllowlistEntry]:
    """The operator's own network, noted so a match reads "My network: <note>"."""
    rows = conn.execute("SELECT value, kind, note FROM allowlist WHERE mine = 1 ORDER BY value")
    return [
        AllowlistEntry(
            r["value"],
            r["kind"],
            f"My network: {r['note']}" if r["note"] else "My network",
            MINE_ORIGIN,
            True,
        )
        for r in rows
    ]


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
