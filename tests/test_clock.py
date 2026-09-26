# SPDX-License-Identifier: AGPL-3.0-only
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

from threatcull.clock import display_zone, ts, utcnow


def test_ts_is_utc_iso_seconds() -> None:
    aest = timezone(timedelta(hours=10))
    assert ts(datetime(2026, 9, 24, 22, 0, 5, 123, tzinfo=aest)) == "2026-09-24T12:00:05+00:00"


def test_ts_rejects_naive_datetimes() -> None:
    with pytest.raises(ValueError, match="timezone"):
        ts(datetime(2026, 9, 24))  # noqa: DTZ001 - deliberately naive


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC


def test_display_zone_defaults_to_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    assert display_zone() is UTC
    monkeypatch.setenv("TZ", "")
    assert display_zone() is UTC


def test_display_zone_reads_an_iana_name_from_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Australia/Melbourne")
    assert display_zone() == ZoneInfo("Australia/Melbourne")
    monkeypatch.setenv("TZ", ":Europe/Berlin")  # glibc's leading colon
    assert display_zone() == ZoneInfo("Europe/Berlin")


def test_display_zone_rejects_an_unknown_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Mars/Olympus_Mons")
    with pytest.raises(ZoneInfoNotFoundError):
        display_zone()
