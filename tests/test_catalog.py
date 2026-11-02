# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.factories import make_entry
from threatcull.catalog import CatalogError, feed_label, load_catalog, shipped_catalog


def test_shipped_catalog_loads_with_unique_ids_and_https_urls() -> None:
    entries = load_catalog()
    assert len(entries) >= 20
    assert len({e.id for e in entries}) == len(entries)
    assert all(e.url.startswith("https://") for e in entries)


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


def test_legacy_licence_fields_are_accepted_and_dropped() -> None:
    """Catalogs before 2.0 carried licence data; they still load."""
    entry = make_entry(
        licence="MIT",
        licence_url="https://a.example/l",
        licence_class="restricted",
        business_use="forbidden",
        default_enabled=True,
    )
    assert entry.default_enabled
    assert not hasattr(entry, "licence")


def test_json_sources_need_keys() -> None:
    with pytest.raises(ValidationError, match="json_keys"):
        make_entry(format="json")


def test_ids_are_slugs() -> None:
    with pytest.raises(ValidationError):
        make_entry(id="Not A Slug")


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


# The Sources of the shipped Catalog, hashed per revision. Installs only replace their
# Catalog with a higher revision, so a change to the Sources must raise the revision.
SOURCES_SHA256 = {
    1: "539af5640aeeb9c97f23bd5e9615db55223f050ba50c09b86924f94957f4bf43",
    # 2.0: licence fields removed
    2: "2050a9953ce18e735bbd0d43fcfbb802f580a91ce0e13b4547244f7f18ef43fc",
    # PR #34 (issue #28): BlackHole TODAY IPs
    3: "03e2d38e39edf3e2f8b871c7c5f41c1fbe68534db6e0cafecedafffe704c72ff",
    # Sources from Bert-JanP/Open-Source-Threat-Intel-Feeds review
    4: "46443d48f7f77b0d6ac0e5e95736cf0238c0c1d9cfa1db94d25e86c896802913",
    # abuse.ch Sources removed: authenticated, not-for-profit access only (terms of use)
    5: "66ef1bec4e69bf379b668e768bba754ea6f6447c33123d7d3c5459be71201a82",
}


def test_changing_catalog_sources_raises_the_revision() -> None:
    catalog = shipped_catalog()
    entries = [entry.model_dump(mode="json") for entry in catalog.entries]
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    assert SOURCES_SHA256.get(catalog.revision) == digest, (
        f"catalog.yaml Sources changed: raise 'revision' above {catalog.revision} and add "
        f'{catalog.revision + 1}: "{digest}" to SOURCES_SHA256 (see CONTRIBUTING.md)'
    )


@pytest.mark.parametrize(
    ("url", "label"),
    [
        ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodotracker.abuse.ch"),
        (
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
            "github.com/stamparm/ipsum",
        ),
        ("https://raw.githubusercontent.com/onlyowner", "raw.githubusercontent.com"),
        ("file:///data/imports/x.txt", "local file"),
    ],
)
def test_feed_label_names_the_publisher(url: str, label: str) -> None:
    assert feed_label(url) == label


def test_feed_label_survives_malformed_urls() -> None:
    assert feed_label("https://[broken/list.txt") == "https://[broken/list.txt"
