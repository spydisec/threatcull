# SPDX-License-Identifier: AGPL-3.0-only
"""Home Network: the operator's own public networks and domains (like Snort's HOME_NET).

Home Network entries are excluded from every Output exactly like Allowlist entries,
and a Compile reports every scored Indicator they exclude as a home hit.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, get_args

from threatcull.clock import ts
from threatcull.indicators import Indicator, IndicatorKind
from threatcull.store.allowlist import AllowlistEntry, normalize_allow_value
from threatcull.store.errors import NotFoundError

HomeOrigin = Literal["manual", "auto"]
HOME_ORIGIN = "home"  # AllowlistEntry.origin of a Home Network entry
PRIVATE_MESSAGE = (
    "private and special-purpose addresses are never published; no Home Network entry is needed"
)


@dataclass(frozen=True, slots=True)
class HomeEntry:
    value: str
    kind: IndicatorKind
    note: str
    origin: HomeOrigin


def normalize_home_value(raw: str) -> Indicator:
    """``normalize_allow_value``, with a clearer message for private/special addresses."""
    try:
        return normalize_allow_value(raw)
    except ValueError as exc:
        if _is_private(raw.strip()):
            raise ValueError(f"{raw.strip()!r}: {PRIVATE_MESSAGE}") from exc
        raise


def _is_private(text: str) -> bool:
    try:
        return not ipaddress.ip_network(text, strict=False).is_global
    except ValueError:
        return False


def add_home(
    conn: sqlite3.Connection,
    raw: str,
    note: str = "",
    *,
    origin: HomeOrigin = "manual",
    now: datetime,
) -> HomeEntry:
    if origin not in get_args(HomeOrigin):
        raise ValueError(f"origin must be one of {', '.join(get_args(HomeOrigin))}")
    indicator = normalize_home_value(raw)
    conn.execute(
        "INSERT INTO home_network (value, kind, note, origin, created_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (value) DO UPDATE SET note = excluded.note, origin = excluded.origin",
        (indicator.value, indicator.kind, note, origin, ts(now)),
    )
    return HomeEntry(indicator.value, indicator.kind, note, origin)


def remove_home(conn: sqlite3.Connection, raw: str) -> None:
    value = normalize_home_value(raw).value
    if conn.execute("DELETE FROM home_network WHERE value = ?", (value,)).rowcount == 0:
        raise NotFoundError(f"{value} is not in the Home Network")


def home_entries(conn: sqlite3.Connection) -> list[HomeEntry]:
    rows = conn.execute("SELECT value, kind, note, origin FROM home_network ORDER BY value")
    return [HomeEntry(r["value"], r["kind"], r["note"], r["origin"]) for r in rows]


def home_allow_entries(conn: sqlite3.Connection) -> list[AllowlistEntry]:
    """Home Network entries as Allowlist entries, so reasons read "Home Network: <note>"."""
    return [
        AllowlistEntry(
            entry.value,
            entry.kind,
            f"Home Network: {entry.note}" if entry.note else "Home Network",
            HOME_ORIGIN,
        )
        for entry in home_entries(conn)
    ]
