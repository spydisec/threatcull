# SPDX-License-Identifier: AGPL-3.0-only
"""The ``when`` filter shows stored UTC timestamps in the ``TZ`` zone."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from threatcull.web.templating import _age, _when, age_label

STAMP = "2026-09-24T21:53:00+00:00"


def test_when_shows_utc_by_default() -> None:
    assert str(_when(STAMP)) == (
        f'<time datetime="{STAMP}" title="{STAMP}">2026-09-24 21:53 UTC</time>'
    )


def test_when_shows_local_time_from_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Australia/Melbourne")
    assert str(_when(STAMP)) == (
        f'<time datetime="{STAMP}" title="{STAMP}">2026-09-25 07:53 AEST</time>'
    )


def test_when_keeps_missing_and_unparseable_values() -> None:
    assert str(_when(None)) == "never"
    assert str(_when("", missing="-")) == "-"
    assert str(_when("soon")) == "soon"


_NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("delta", "label"),
    [
        (timedelta(hours=-5), "less than a day"),  # clock moved back
        (timedelta(hours=5), "less than a day"),
        (timedelta(days=1), "1 day"),
        (timedelta(days=13), "13 days"),
        (timedelta(days=14), "2 weeks"),
        (timedelta(days=59), "8 weeks"),
        (timedelta(days=60), "2 months"),
        (timedelta(days=729), "24 months"),
        (timedelta(days=730), "2 years"),
        (timedelta(days=1830), "5 years"),
    ],
)
def test_age_label_buckets(delta: timedelta, label: str) -> None:
    assert age_label(_NOW - delta, _NOW) == label


def test_age_of_a_timestamp_without_a_zone_is_read_as_utc() -> None:
    assert "years" in str(_age("2021-10-06T00:00:00"))
