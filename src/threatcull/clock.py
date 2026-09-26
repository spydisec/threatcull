# SPDX-License-Identifier: AGPL-3.0-only
"""The one place timestamps are made: UTC, ISO-8601, second precision.

Stored times stay UTC. Only the web UI converts them, to the zone in ``TZ``.
"""

import os
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo

TZ_ENV_VAR = "TZ"


def utcnow() -> datetime:
    return datetime.now(UTC)


def ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamps need a timezone")
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def display_zone() -> tzinfo:
    """The zone the web UI shows times in: the IANA name in ``TZ``, such as
    ``Australia/Melbourne``, or UTC when unset.

    Raises ``ZoneInfoNotFoundError`` (or ``ValueError``) for a name the tz
    database does not know.
    """
    name = os.environ.get(TZ_ENV_VAR, "").strip().removeprefix(":")
    if name in ("", "UTC"):
        return UTC
    return ZoneInfo(name)


def local(stamp: str) -> datetime:
    """A stored ISO-8601 timestamp in the display zone."""
    return datetime.fromisoformat(stamp).astimezone(display_zone())
