# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
from dataclasses import replace

import pytest

from threatcull.store.settings import Settings, load_settings, save_settings


def test_defaults_match_owner_decisions(conn: sqlite3.Connection) -> None:
    settings = load_settings(conn)
    assert settings == Settings()
    assert settings.business_mode is True
    assert (settings.active_window_days, settings.retention_days) == (7, 30)
    assert settings.stale_after_hours == 72
    assert (settings.tier_high, settings.tier_medium) == (3, 2)
    assert (settings.max_shrink, settings.max_stale_ratio) == (0.5, 0.3)


def test_save_and_load_round_trip(conn: sqlite3.Connection) -> None:
    changed = replace(Settings(), business_mode=False, tier_high=4)
    save_settings(conn, changed)
    assert load_settings(conn) == changed


def test_unknown_stored_keys_are_ignored(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO settings (key, value) VALUES ('obsolete', '1')")
    assert load_settings(conn) == Settings()


@pytest.mark.parametrize(
    "changes",
    [
        {"tier_medium": 3},
        {"tier_medium": 0},
        {"active_window_days": 0},
        {"retention_days": 3},
        {"max_shrink": 1.5},
        {"max_stale_ratio": 0.0},
    ],
)
def test_invalid_settings_are_rejected(changes: dict[str, int | float]) -> None:
    with pytest.raises(ValueError, match="setting"):
        replace(Settings(), **changes)  # type: ignore[arg-type]
