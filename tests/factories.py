# SPDX-License-Identifier: AGPL-3.0-only
"""Builders for test data."""

from typing import Any

from threatcull.catalog import CatalogEntry


def make_entry(**overrides: Any) -> CatalogEntry:
    base: dict[str, Any] = {
        "id": "test-source",
        "name": "Test Source",
        "url": "https://example.com/list.txt",
        "format": "plain",
        "kind": "ip",
        "category": "malicious",
        "licence_class": "permissive",
        "business_use": "allowed",
        "licence": "Test licence",
        "licence_url": "https://example.com/licence",
        "refresh_minutes": 60,
    }
    base.update(overrides)
    return CatalogEntry.model_validate(base)
