# SPDX-License-Identifier: AGPL-3.0-only
"""Catalog updates between releases: revision, saved copy, sync without enabling."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.factories import dump_yaml
from threatcull.catalog import CatalogError, parse_catalog, shipped_catalog
from threatcull.catalog_update import (
    CATALOG_FILE,
    MAX_CATALOG_BYTES,
    active_catalog,
    apply_update,
    download_catalog,
)
from threatcull.fetcher import FetchResult
from threatcull.store.sources import get_source, sync_catalog


def _source(source_id: str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": source_id,
        "name": source_id.replace("-", " ").title(),
        "url": f"https://feeds.example/{source_id}.txt",
        "format": "plain",
        "kind": "ip",
        "category": "malicious",
        "licence_class": "permissive",
        "business_use": "allowed",
        "licence": "CC0",
        "licence_url": "https://feeds.example/licence",
        "refresh_minutes": 60,
    }
    entry.update(overrides)
    return entry


def _catalog(revision: int, *sources: dict[str, Any], **top: Any) -> str:
    return dump_yaml({"revision": revision, **top, "sources": list(sources)})


def _next_revision() -> int:
    return shipped_catalog().revision + 1


def _shipped_ids() -> list[str]:
    return [entry.id for entry in shipped_catalog().entries]


# --- parsing -------------------------------------------------------------------------


def test_the_shipped_catalog_has_a_revision() -> None:
    assert shipped_catalog().revision >= 1


def test_a_catalog_without_revision_counts_as_zero() -> None:
    assert parse_catalog(dump_yaml({"sources": [_source("a")]})).revision == 0


@pytest.mark.parametrize("revision", [-1, "2", 1.5, True])
def test_revision_must_be_a_whole_number(revision: object) -> None:
    with pytest.raises(CatalogError, match="whole number"):
        parse_catalog(dump_yaml({"revision": revision, "sources": []}))


def test_a_catalog_for_a_newer_threatcull_is_refused() -> None:
    with pytest.raises(CatalogError, match=r"needs ThreatCull 99\.0\.0 or newer"):
        parse_catalog(_catalog(5, _source("a"), requires="99.0.0"))
    assert parse_catalog(_catalog(5, _source("a"), requires="1.0")).requires == "1.0"


def test_yaml_aliases_and_broken_yaml_are_catalog_errors() -> None:
    with pytest.raises(CatalogError, match="aliases"):
        parse_catalog("a: &x [1]\nb: *x\nsources: []\n")
    with pytest.raises(CatalogError, match="not valid YAML"):
        parse_catalog("sources: [\n")
    with pytest.raises(CatalogError, match="nests too deeply"):
        parse_catalog("[" * 100_000)


def test_file_urls_are_refused_only_in_updates() -> None:
    text = _catalog(2, _source("local", url="file:///etc/passwd"))
    assert parse_catalog(text).entries[0].url == "file:///etc/passwd"
    with pytest.raises(CatalogError, match="file:// URLs: local"):
        parse_catalog(text, allow_file_urls=False)


# --- choosing the Catalog in use -----------------------------------------------------


def test_active_catalog_prefers_a_newer_saved_update(tmp_path: Path) -> None:
    assert active_catalog(tmp_path).origin == "shipped"
    (tmp_path / CATALOG_FILE).write_text(_catalog(_next_revision(), _source("a")))
    active = active_catalog(tmp_path)
    assert (active.origin, [e.id for e in active.catalog.entries]) == ("updated", ["a"])


def test_a_release_with_a_newer_catalog_takes_over(tmp_path: Path) -> None:
    (tmp_path / CATALOG_FILE).write_text(_catalog(shipped_catalog().revision, _source("a")))
    assert active_catalog(tmp_path).origin == "shipped"


def test_a_broken_saved_catalog_is_ignored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / CATALOG_FILE).write_text("sources: [\n")
    assert active_catalog(tmp_path).origin == "shipped"
    assert "ignoring the saved Catalog" in caplog.text


# --- applying an update --------------------------------------------------------------


def test_update_adds_disabled_refreshes_and_removes(
    conn: sqlite3.Connection, tmp_path: Path
) -> None:
    shipped = shipped_catalog()
    sync_catalog(conn, shipped.entries)
    kept, gone = shipped.entries[0], shipped.entries[1]
    assert get_source(conn, gone.id).enabled is gone.default_enabled
    renamed = {**kept.model_dump(mode="json"), "name": "Renamed"}
    others = [e.model_dump(mode="json") for e in shipped.entries[2:]]
    fresh = _source("fresh-list", default_enabled=True)
    text = _catalog(_next_revision(), renamed, *others, fresh)

    report = apply_update(conn, tmp_path, text)

    assert (report.added, report.changed, report.removed) == (
        ("fresh-list",),
        (kept.id,),
        (gone.id,),
    )
    assert get_source(conn, "fresh-list").enabled is False  # the operator decides
    assert get_source(conn, kept.id).name == "Renamed"
    assert get_source(conn, gone.id).enabled is False
    assert (tmp_path / CATALOG_FILE).read_text() == text
    assert "1 new Source (disabled), 1 updated, 1 removed" in report.summary()

    # A restart syncs the saved update, and still leaves the new Source to the operator.
    sync_catalog(conn, active_catalog(tmp_path).catalog.entries)
    assert get_source(conn, "fresh-list").enabled is False
    assert get_source(conn, kept.id).name == "Renamed"


def test_the_same_revision_is_up_to_date(conn: sqlite3.Connection, tmp_path: Path) -> None:
    report = apply_update(conn, tmp_path, _catalog(shipped_catalog().revision, _source("a")))
    assert report.up_to_date
    assert report.summary() == f"The Catalog is up to date (revision {report.revision})."
    assert not (tmp_path / CATALOG_FILE).exists()


def test_an_older_catalog_is_refused(conn: sqlite3.Connection, tmp_path: Path) -> None:
    (tmp_path / CATALOG_FILE).write_text(_catalog(_next_revision() + 1, _source("a")))
    with pytest.raises(CatalogError, match="older than the one in use"):
        apply_update(conn, tmp_path, _catalog(_next_revision(), _source("b")))


def test_a_refused_update_changes_nothing(conn: sqlite3.Connection, tmp_path: Path) -> None:
    sync_catalog(conn, shipped_catalog().entries)
    text = _catalog(_next_revision(), _source("local", url="file:///etc/passwd"))
    with pytest.raises(CatalogError):
        apply_update(conn, tmp_path, text)
    assert not (tmp_path / CATALOG_FILE).exists()
    ids = [row[0] for row in conn.execute("SELECT id FROM sources ORDER BY id")]
    assert ids == sorted(_shipped_ids())


def test_an_oversized_update_is_refused(conn: sqlite3.Connection, tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="at most"):
        apply_update(conn, tmp_path, "#" * (MAX_CATALOG_BYTES + 1))


# --- downloading ---------------------------------------------------------------------


def test_download_uses_https_only() -> None:
    with pytest.raises(CatalogError, match="https"):
        download_catalog("http://feeds.example/catalog.yaml")


def test_download_returns_the_body() -> None:
    urls: list[str] = []

    def fetch(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        urls.append(url)
        return FetchResult("ok", "revision: 9\n")

    assert download_catalog("https://feeds.example/c.yaml", fetcher=fetch) == "revision: 9\n"
    assert urls == ["https://feeds.example/c.yaml"]
