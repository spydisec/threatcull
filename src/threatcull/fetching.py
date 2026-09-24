# SPDX-License-Identifier: AGPL-3.0-only
"""The Fetch pipeline: download → parse → normalise → record Sightings."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from threatcull.fetcher import Fetcher, FetchError
from threatcull.indicators import Indicator, normalize
from threatcull.parsers import ParseError, parse
from threatcull.store.errors import PolicyError
from threatcull.store.runs import finish_run, start_run
from threatcull.store.sightings import (
    record_fetch_failure,
    record_fetch_success,
    record_not_modified,
)
from threatcull.store.sources import Source, get_source, list_sources


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    source_id: str
    status: Literal["ok", "not_modified", "failed"]
    parsed: int = 0
    valid: int = 0
    invalid: int = 0
    added: int = 0
    removed: int = 0
    error: str | None = None


def fetch_source(
    conn: sqlite3.Connection, source: Source, fetcher: Fetcher, *, now: datetime
) -> FetchOutcome:
    run_id = start_run(conn, "fetch", now=now, source_id=source.id)
    try:
        result = fetcher(source.url, etag=source.etag, last_modified=source.last_modified)
        if result.status == "not_modified":
            record_not_modified(conn, source.id, now=now)
            finish_run(conn, run_id, "not_modified", now=now)
            return FetchOutcome(source.id, "not_modified")
        candidates = list(
            parse(
                source.format, result.text, csv_column=source.csv_column, json_keys=source.json_keys
            )
        )
    except (FetchError, ParseError) as exc:
        return _fail(conn, run_id, source.id, str(exc), now=now)
    indicators: set[Indicator] = set()
    invalid = 0
    for raw in candidates:
        indicator = normalize(raw, source.kind)
        if indicator is None:
            invalid += 1
        else:
            indicators.add(indicator)
    if not indicators:
        # A 200 with an HTML error page or an empty body must not wipe the Source's Sightings.
        error = f"no valid indicators in response ({len(candidates)} lines unparseable)"
        return _fail(conn, run_id, source.id, error, now=now)
    added, removed = record_fetch_success(
        conn, source.id, indicators, now=now, etag=result.etag, last_modified=result.last_modified
    )
    outcome = FetchOutcome(
        source.id,
        "ok",
        parsed=len(candidates),
        valid=len(indicators),
        invalid=invalid,
        added=added,
        removed=removed,
    )
    counts = {
        "parsed": outcome.parsed,
        "valid": outcome.valid,
        "invalid": invalid,
        "added": added,
        "removed": removed,
    }
    finish_run(conn, run_id, "ok", now=now, counts=counts)
    return outcome


def fetch_all(
    conn: sqlite3.Connection,
    fetcher: Fetcher,
    *,
    now: datetime,
    source_ids: Sequence[str] | None = None,
) -> list[FetchOutcome]:
    """Fetch every enabled Source, or only ``source_ids`` (which must be enabled)."""
    if source_ids:
        sources = [get_source(conn, source_id) for source_id in source_ids]
        disabled = [s.id for s in sources if not s.enabled]
        if disabled:
            raise PolicyError(f"Sources are disabled: {', '.join(disabled)}")
    else:
        sources = list_sources(conn, enabled_only=True)
    return [fetch_source(conn, source, fetcher, now=now) for source in sources]


def _fail(
    conn: sqlite3.Connection, run_id: int, source_id: str, error: str, *, now: datetime
) -> FetchOutcome:
    record_fetch_failure(conn, source_id, error, now=now)
    finish_run(conn, run_id, "failed", now=now, error=error)
    return FetchOutcome(source_id, "failed", error=error)
