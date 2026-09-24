# SPDX-License-Identifier: AGPL-3.0-only
"""The one place timestamps are made: UTC, ISO-8601, second precision."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamps need a timezone")
    return dt.astimezone(UTC).isoformat(timespec="seconds")
