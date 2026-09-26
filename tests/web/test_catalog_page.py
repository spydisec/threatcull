# SPDX-License-Identifier: AGPL-3.0-only
"""The Catalog card on the Sources page: download or upload an update."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from tests.factories import dump_yaml
from threatcull.catalog import shipped_catalog
from threatcull.catalog_update import CATALOG_FILE
from threatcull.fetcher import FetchError
from threatcull.store.sources import get_source
from threatcull.web.deps import open_db


def _update(revision: int, extra_id: str = "fresh-list") -> str:
    sources = [e.model_dump(mode="json") for e in shipped_catalog().entries]
    fresh = {**sources[0], "id": extra_id, "family": extra_id, "default_enabled": True}
    return dump_yaml({"revision": revision, "sources": [*sources, fresh]})


def _enabled(tmp_path: Path, source_id: str) -> bool:
    conn = open_db(tmp_path)
    try:
        return get_source(conn, source_id).enabled
    finally:
        conn.close()


def test_the_card_shows_the_revision_and_keeps_the_title(
    client: TestClient, logged_in: str
) -> None:
    page = client.get("/sources").text
    assert f"revision {shipped_catalog().revision}, shipped with ThreatCull" in page
    assert page.split("<title>", 1)[1].split("</title>", 1)[0] == "Sources · ThreatCull"


def test_check_for_updates_applies_a_newer_catalog(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    newer = shipped_catalog().revision + 1
    client.app.state.catalog_downloader = lambda: _update(newer)  # type: ignore[attr-defined]
    response = client.post(
        "/sources/catalog/update", data={"csrf": logged_in}, follow_redirects=False
    )
    assert response.status_code == 303
    page = client.get("/sources").text
    assert f"to {newer}: 1 new Source (disabled), 0 updated, 0 removed" in page
    assert f"revision {newer}, saved by an update" in page
    assert _enabled(tmp_path, "fresh-list") is False
    assert (tmp_path / CATALOG_FILE).is_file()


def test_download_failure_is_shown(client: TestClient, logged_in: str) -> None:
    def offline() -> str:
        raise FetchError("ConnectError")

    client.app.state.catalog_downloader = offline  # type: ignore[attr-defined]
    response = client.post("/sources/catalog/update", data={"csrf": logged_in})
    assert response.status_code == 400
    assert "Could not download the Catalog: ConnectError" in response.text


def test_upload_applies_a_file_and_refuses_bad_ones(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    newer = shipped_catalog().revision + 1
    ok = client.post(
        "/sources/catalog/upload",
        data={"csrf": logged_in},
        files={"file": ("catalog.yaml", _update(newer).encode(), "text/yaml")},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    assert _enabled(tmp_path, "fresh-list") is False

    older = client.post(
        "/sources/catalog/upload",
        data={"csrf": logged_in},
        files={"file": ("catalog.yaml", _update(newer - 1, "other").encode(), "text/yaml")},
    )
    assert older.status_code == 400
    assert "older than the one in use" in older.text

    invalid = client.post(
        "/sources/catalog/upload",
        data={"csrf": logged_in},
        files={"file": ("c.yaml", b"revision: 99\nsources: [{id: Bad}]\n", "text/yaml")},
    )
    assert invalid.status_code == 400
    assert "The Catalog has an invalid Source" in invalid.text

    binary = client.post(
        "/sources/catalog/upload",
        data={"csrf": logged_in},
        files={"file": ("c.yaml", b"\xff\xfe\x00", "text/yaml")},
    )
    assert binary.status_code == 400
    assert "not UTF-8" in binary.text


def test_catalog_actions_need_csrf(client: TestClient, logged_in: str) -> None:
    called: list[bool] = []

    def download() -> str:
        called.append(True)
        return ""

    client.app.state.catalog_downloader = download  # type: ignore[attr-defined]
    assert client.post("/sources/catalog/update", follow_redirects=False).status_code == 403
    upload = client.post(
        "/sources/catalog/upload",
        files={"file": ("c.yaml", b"revision: 99\n", "text/yaml")},
        follow_redirects=False,
    )
    assert upload.status_code == 403
    assert called == []
