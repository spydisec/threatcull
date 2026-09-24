# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.factories import make_entry
from threatcull.catalog import (
    BusinessUse,
    CatalogError,
    business_use_permitted,
    load_catalog,
)


def test_shipped_catalog_loads_with_unique_ids_and_https_urls() -> None:
    entries = load_catalog()
    assert len(entries) >= 20
    assert len({e.id for e in entries}) == len(entries)
    assert all(e.url.startswith("https://") for e in entries)
    assert all(e.licence_url.startswith("https://") for e in entries)


def test_shipped_catalog_has_builtin_allowlist_sources() -> None:
    allowlist = [e for e in load_catalog() if e.role == "allowlist"]
    assert {e.id for e in allowlist} >= {"cloudflare-ipv4", "cloudflare-ipv6", "fastly-public-ips"}
    assert all(e.default_enabled for e in allowlist)


def test_shipped_catalog_never_lists_a_url_twice() -> None:
    urls = [e.url for e in load_catalog()]
    assert len(set(urls)) == len(urls)


def test_family_defaults_to_id() -> None:
    assert make_entry(id="solo-list").family == "solo-list"
    assert make_entry(id="ipsum-level3", family="ipsum").family == "ipsum"


def test_default_enabled_blocklist_must_be_cleared_for_business_use() -> None:
    with pytest.raises(ValidationError, match="business"):
        make_entry(default_enabled=True, business_use="unknown")


def test_default_enabled_allowlist_source_is_exempt() -> None:
    entry = make_entry(
        role="allowlist", category="infrastructure", business_use="unknown", default_enabled=True
    )
    assert entry.default_enabled


def test_json_sources_need_keys() -> None:
    with pytest.raises(ValidationError, match="json_keys"):
        make_entry(format="json")


def test_ids_are_slugs() -> None:
    with pytest.raises(ValidationError):
        make_entry(id="Not A Slug")


@pytest.mark.parametrize(
    ("role", "business_use", "expected"),
    [
        ("blocklist", BusinessUse.ALLOWED, True),
        ("blocklist", BusinessUse.FORBIDDEN, False),
        ("blocklist", BusinessUse.UNKNOWN, False),
        ("allowlist", BusinessUse.UNKNOWN, True),
    ],
)
def test_business_use_permitted(role: str, business_use: BusinessUse, expected: bool) -> None:
    assert business_use_permitted(role, business_use) is expected  # type: ignore[arg-type]


def test_load_catalog_from_path_and_reject_duplicates(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(
        "sources:\n"
        "  - {id: a-list, name: A, url: 'https://a.example/x', format: plain, kind: ip,\n"
        "     category: malicious, licence_class: permissive, business_use: allowed,\n"
        "     licence: MIT, licence_url: 'https://a.example/l', refresh_minutes: 60}\n",
        encoding="utf-8",
    )
    assert [e.id for e in load_catalog(good)] == ["a-list"]
    dupe = tmp_path / "dupe.yaml"
    dupe.write_text(good.read_text() + good.read_text().split("sources:\n", 1)[1], encoding="utf-8")
    with pytest.raises(CatalogError, match="duplicate"):
        load_catalog(dupe)


def test_load_catalog_rejects_wrong_shape(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just a list\n", encoding="utf-8")
    with pytest.raises(CatalogError, match="sources"):
        load_catalog(bad)
