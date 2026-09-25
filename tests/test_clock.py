# SPDX-License-Identifier: AGPL-3.0-only
from datetime import UTC, datetime, timedelta, timezone

import pytest

from threatcull.clock import ts, utcnow


def test_ts_is_utc_iso_seconds() -> None:
    aest = timezone(timedelta(hours=10))
    assert ts(datetime(2026, 9, 24, 22, 0, 5, 123, tzinfo=aest)) == "2026-09-24T12:00:05+00:00"


def test_ts_rejects_naive_datetimes() -> None:
    with pytest.raises(ValueError, match="timezone"):
        ts(datetime(2026, 9, 24))  # noqa: DTZ001 - deliberately naive


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC
