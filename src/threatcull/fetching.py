# SPDX-License-Identifier: AGPL-3.0-only
"""The Fetch pipeline: download → parse → normalise → stage → record Sightings.

Parsing, normalising and staging stream one candidate at a time, so a Source listing
millions of Indicators never needs a Python list or set of them.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from threatcull import __version__
from threatcull.fetcher import Fetcher, FetchError, FetchResult
from threatcull.indicators import Indicator, SourceKind, normalize
from threatcull.parsers import ParseError, parse
from threatcull.store.errors import PolicyError
from threatcull.store.runs import finish_run, start_run
from threatcull.store.sightings import (
    apply_fetched,
    record_fetch_failure,
    record_not_modified,
    same_content,
    sightings_unchanged,
    stage_fetched,
)
from threatcull.store.sources import Source, get_source, list_sources

# Line-oriented formats where an HTML page can still yield a few hostname-like lines.
_LINE_FORMATS = frozenset({"plain", "hosts", "adblock"})
_HTML_START = re.compile(r"[\s\ufeff]*<")
NOT_A_LIST = "looks like an HTML page, not a list"
# Per-Source shrink guard: a Source with at least this many current Sightings that
# suddenly lists under COLLAPSE_RATIO of them is treated as a failed Fetch.
COLLAPSE_MIN_CURRENT = 1000
COLLAPSE_RATIO = 0.1


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


class _Tally:
    """Counts candidates while they stream from the parser to the staging table."""

    def __init__(self) -> None:
        self.parsed = 0
        self.invalid = 0

    def normalised(self, candidates: Iterable[str], kind: SourceKind) -> Iterator[Indicator]:
        for raw in candidates:
            self.parsed += 1
            indicator = normalize(raw, kind)
            if indicator is None:
                self.invalid += 1
            else:
                yield indicator


def content_digest(source: Source, text: str) -> str:
    """SHA-256 of a download plus everything that decides how it parses.

    The ThreatCull version is part of it, so an upgrade that changes parsing or
    validation reprocesses every list once instead of trusting the old result.
    """
    digest = hashlib.sha256()
    parts = (__version__, source.url, source.format, source.kind, str(source.csv_column))
    for part in (*parts, *source.json_keys):
        digest.update(part.encode())
        digest.update(b"\0")
    digest.update(text.encode("utf-8", "surrogatepass"))
    return digest.hexdigest()


def fetch_source(
    conn: sqlite3.Connection, source: Source, fetcher: Fetcher, *, now: datetime
) -> FetchOutcome:
    run_id = start_run(conn, "fetch", now=now, source_id=source.id)
    tally = _Tally()
    valid = 0
    try:
        # A 304 only refreshes the Sightings already there: when some were pruned
        # meanwhile, ask for the whole list so they come back.
        trusted = sightings_unchanged(conn, source.id)
        result = fetcher(
            source.url,
            etag=source.etag if trusted else None,
            last_modified=source.last_modified if trusted else None,
        )
        if result.status == "not_modified":
            record_not_modified(conn, source.id, now=now)
            finish_run(conn, run_id, "not_modified", now=now)
            return FetchOutcome(source.id, "not_modified")
        digest = content_digest(source, result.text)
        if same_content(conn, source.id, digest):
            # Same bytes as the list already applied (a server without ETags, or
            # one that ignores them): skip parsing millions of lines again.
            record_not_modified(
                conn, source.id, now=now, validators=(result.etag, result.last_modified)
            )
            finish_run(conn, run_id, "not_modified", now=now)
            return FetchOutcome(source.id, "not_modified")
        error = NOT_A_LIST if _looks_like_html(source, result) else None
        if error is None:
            candidates = parse(
                source.format,
                result.text,
                csv_column=source.csv_column,
                json_keys=source.json_keys,
            )
            valid = stage_fetched(conn, tally.normalised(candidates, source.kind))
            error = _count_rejection(conn, source.id, valid, tally.parsed)
    except (FetchError, ParseError) as exc:
        error = str(exc)
    except Exception as exc:
        # One bad Source must not abort the whole Fetch (KeyboardInterrupt still does).
        error = f"{type(exc).__name__}: {exc}"
    if error is not None:
        return _fail(conn, run_id, source.id, error, now=now)
    try:
        added, removed = apply_fetched(
            conn,
            source.id,
            now=now,
            etag=result.etag,
            last_modified=result.last_modified,
            content_sha256=digest,
        )
    except Exception as exc:
        return _fail(conn, run_id, source.id, f"{type(exc).__name__}: {exc}", now=now)
    outcome = FetchOutcome(
        source.id,
        "ok",
        parsed=tally.parsed,
        valid=valid,
        invalid=tally.invalid,
        added=added,
        removed=removed,
    )
    counts = {
        "parsed": outcome.parsed,
        "valid": outcome.valid,
        "invalid": outcome.invalid,
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


def _looks_like_html(source: Source, result: FetchResult) -> bool:
    if source.format not in _LINE_FORMATS:
        return False
    media_type = (result.content_type or "").split(";", 1)[0].strip().lower()
    return media_type == "text/html" or _HTML_START.match(result.text) is not None


def _count_rejection(
    conn: sqlite3.Connection, source_id: str, valid: int, parsed: int
) -> str | None:
    """Why a parsed response must not replace the Source's Sightings, if it must not."""
    if not valid:
        # A 200 with an HTML error page or an empty body must not wipe the Source's Sightings.
        return f"no valid indicators in response ({parsed} lines unparseable)"
    current = int(
        conn.execute(
            "SELECT COUNT(*) FROM sightings WHERE source_id = ? AND current = 1", (source_id,)
        ).fetchone()[0]
    )
    if current >= COLLAPSE_MIN_CURRENT and valid < current * COLLAPSE_RATIO:
        return (
            f"only {valid} valid indicators against {current} current Sightings "
            f"(below {COLLAPSE_RATIO:.0%}); keeping the previous list"
        )
    return None


def _fail(
    conn: sqlite3.Connection, run_id: int, source_id: str, error: str, *, now: datetime
) -> FetchOutcome:
    record_fetch_failure(conn, source_id, error, now=now)
    finish_run(conn, run_id, "failed", now=now, error=error)
    return FetchOutcome(source_id, "failed", error=error)
