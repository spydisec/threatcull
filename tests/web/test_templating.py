# SPDX-License-Identifier: AGPL-3.0-only
"""The ``when`` filter shows stored UTC timestamps in the ``TZ`` zone."""

from __future__ import annotations

import pytest

from threatcull.web.templating import _when

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
