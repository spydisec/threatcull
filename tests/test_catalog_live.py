# SPDX-License-Identifier: AGPL-3.0-only
"""Checks every shipped Catalog URL against the real internet. Run: uv run pytest -m network"""

import pytest

from threatcull.catalog import CatalogEntry, load_catalog
from threatcull.fetcher import HttpFetcher
from threatcull.indicators import normalize
from threatcull.parsers import parse

CATALOG = load_catalog()


@pytest.mark.network
@pytest.mark.parametrize("entry", CATALOG, ids=[e.id for e in CATALOG])
def test_catalog_source_is_live_and_yields_indicators(entry: CatalogEntry) -> None:
    result = HttpFetcher(retry_delays=())(entry.url, etag=None, last_modified=None)
    assert result.status == "ok"
    candidates = parse(
        entry.format, result.text, csv_column=entry.csv_column, json_keys=entry.json_keys
    )
    valid = {i for raw in candidates if (i := normalize(raw, entry.kind)) is not None}
    assert valid, f"{entry.id} yielded no valid Indicators"
