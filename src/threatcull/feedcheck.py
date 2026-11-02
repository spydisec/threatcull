# SPDX-License-Identifier: AGPL-3.0-only
"""Download a feed once and count what ThreatCull would keep from it.

Used by the maintainer scripts: the Catalog request bot (``scripts/catalog_request.py``)
and the Catalog health check (``scripts/catalog_health.py``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from threatcull.catalog import CatalogEntry
from threatcull.fetcher import Fetcher, FetchError
from threatcull.fetching import looks_like_html, starts_with_markup, text_of
from threatcull.indicators import SourceKind, normalize
from threatcull.parsers import ParseError, SourceFormat, parse

ProblemKind = Literal["download", "parse", "html", "empty"]


@dataclass(frozen=True)
class Feed:
    """What probe_feed needs: enough to download and parse a list."""

    url: str
    format: SourceFormat
    kind: SourceKind
    csv_column: int = 0
    json_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class FeedProbe:
    valid: int
    rejected: int
    error: str | None  # the download failed
    html: bool = False
    # SHA-256 of the sorted, de-duplicated valid entries: comment headers, order and
    # duplicates do not change it, so it only moves when the list itself changes.
    set_sha256: str = ""
    parse_error: str | None = None  # downloaded, but not valid JSON or CSV

    @property
    def problem(self) -> tuple[ProblemKind, str] | None:
        """Why this feed is unusable, as (kind, short detail), or None when it is usable.

        The one place that decides: the request bot words each kind for submitters,
        the health check counts any of them as a failed run.
        """
        if self.error:
            return ("download", self.error)
        if self.parse_error:
            return ("parse", self.parse_error)
        if self.html:
            return ("html", "HTML page, not a list")
        if self.valid == 0:
            return ("empty", f"0 valid entries ({self.rejected} lines rejected)")
        return None


def probe_feed(entry: Feed | CatalogEntry, fetch: Fetcher) -> FeedProbe:
    """Download the feed once and count what ThreatCull would keep from it."""
    try:
        result = fetch(entry.url, etag=None, last_modified=None)
    except FetchError as exc:
        return FeedProbe(0, 0, str(exc))
    try:
        # Line formats: an HTML content type or markup. JSON and CSV: markup only (a
        # JSON or CSV list never starts with "<"), so a mislabelled list still parses.
        if looks_like_html(entry.format, result) or starts_with_markup(result):
            return FeedProbe(0, 0, None, html=True)
        kept: set[str] = set()
        valid = rejected = 0
        for raw in parse(
            entry.format, text_of(result), csv_column=entry.csv_column, json_keys=entry.json_keys
        ):
            indicator = normalize(raw, entry.kind)
            if indicator is None:
                rejected += 1
            else:
                valid += 1  # every valid line, duplicates included, as before
                kept.add(indicator.value)
    except ParseError as exc:
        return FeedProbe(0, 0, None, parse_error=str(exc))
    finally:
        result.close()
    digest = hashlib.sha256("\n".join(sorted(kept)).encode()).hexdigest() if kept else ""
    return FeedProbe(valid, rejected, None, set_sha256=digest)
