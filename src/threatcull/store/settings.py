# SPDX-License-Identifier: AGPL-3.0-only
"""Operator Settings, persisted as JSON values in the settings table."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, fields

from threatcull.store.db import transaction


@dataclass(frozen=True, slots=True)
class Settings:
    active_window_days: int = 7
    retention_days: int = 30
    stale_after_hours: int = 72
    tier_high: int = 3
    tier_medium: int = 2
    max_shrink: float = 0.5
    max_stale_ratio: float = 0.3

    def __post_init__(self) -> None:
        if not 1 <= self.tier_medium < self.tier_high:
            raise ValueError("setting tiers need 1 <= tier_medium < tier_high")
        if self.active_window_days < 1 or self.stale_after_hours < 1:
            raise ValueError("setting windows must be positive")
        if self.retention_days < self.active_window_days:
            raise ValueError("setting retention_days must be >= active_window_days")
        if not 0 < self.max_shrink < 1 or not 0 < self.max_stale_ratio < 1:
            raise ValueError("setting ratios must be between 0 and 1")


_KNOWN = frozenset(f.name for f in fields(Settings))


def load_settings(conn: sqlite3.Connection) -> Settings:
    stored = {
        row["key"]: json.loads(row["value"])
        for row in conn.execute("SELECT key, value FROM settings")
        if row["key"] in _KNOWN
    }
    return Settings(**stored)


def save_settings(conn: sqlite3.Connection, settings: Settings) -> None:
    with transaction(conn):
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [(key, json.dumps(value)) for key, value in asdict(settings).items()],
        )
