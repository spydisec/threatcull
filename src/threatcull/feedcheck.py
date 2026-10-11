# SPDX-License-Identifier: AGPL-3.0-only
"""Download a feed once and count what ThreatCull would keep from it.

Used by the maintainer scripts: the Catalog request bot (``scripts/catalog_request.py``)
and the weekly Catalog health check (``scripts/catalog_health.py``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from threatcull.catalog import CatalogEntry
from threatcull.fetcher import Fetcher, FetchError
from threatcull.fetching import looks_like_html
from threatcull.indicators import SourceKind, normalize
from threatcull.parsers import ParseError, SourceFormat, parse


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
    error: str | None
    html: bool = False
    # SHA-256 of the sorted, de-duplicated valid entries: comment headers, order and
    # duplicates do not change it, so it only moves when the list itself changes.
    set_sha256: str = ""


def probe_feed(entry: Feed | CatalogEntry, fetch: Fetcher) -> FeedProbe:
    """Download the feed once and count what ThreatCull would keep from it."""
    try:
        result = fetch(entry.url, etag=None, last_modified=None)
    except FetchError as exc:
        return FeedProbe(0, 0, str(exc))
    try:
        if looks_like_html(entry.format, result):
            return FeedProbe(0, 0, None, html=True)
        kept: set[str] = set()
        valid = rejected = 0
        for raw in parse(
            entry.format, result.text, csv_column=entry.csv_column, json_keys=entry.json_keys
        ):
            indicator = normalize(raw, entry.kind)
            if indicator is None:
                rejected += 1
            else:
                valid += 1  # every valid line, duplicates included, as before
                kept.add(indicator.value)
    except ParseError as exc:  # e.g. a JSON Source serving an HTML challenge page
        return FeedProbe(0, 0, str(exc))
    finally:
        result.close()
    digest = hashlib.sha256("\n".join(sorted(kept)).encode()).hexdigest() if kept else ""
    return FeedProbe(valid, rejected, None, set_sha256=digest)
