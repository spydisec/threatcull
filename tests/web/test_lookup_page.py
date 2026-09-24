# SPDX-License-Identifier: AGPL-3.0-only
"""The Lookup page and ``/api/v1/lookup``, seeded through file:// Sources."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.store.allowlist import add_entry
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner


@pytest.fixture
def seeded(tmp_path: Path) -> None:
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "a.txt").write_text("45.9.20.1\n45.9.21.7\n")
    (feeds / "b.txt").write_text("45.9.20.1\n")
    conn = open_db(tmp_path)
    try:
        sync_catalog(
            conn,
            [
                make_entry(
                    id="a", url=(feeds / "a.txt").as_uri(), default_enabled=True, name="Source A"
                ),
                make_entry(
                    id="b", url=(feeds / "b.txt").as_uri(), default_enabled=True, name="Source B"
                ),
            ],
        )
        ensure_default_outputs(conn)
        add_entry(conn, "45.9.21.7", "our <b>partner</b>", now=utcnow())
    finally:
        conn.close()
    result = PipelineRunner(tmp_path).run()  # real fetcher, file:// only: no network
    assert result.status == "ok", result


def test_lookup_page_shows_sources_score_and_outputs(
    client: TestClient, logged_in: str, seeded: None
) -> None:
    page = client.get("/lookup", params={"q": " 45.9.20.1 "})
    assert page.status_code == 200
    assert "Source A" in page.text
    assert "Source B" in page.text
    assert "score 2" in page.text
    assert "current" in page.text


def test_lookup_page_shows_the_allowlist_reason_escaped(
    client: TestClient, logged_in: str, seeded: None
) -> None:
    page = client.get("/lookup", params={"q": "45.9.21.7"})
    assert page.status_code == 200
    assert "our &lt;b&gt;partner&lt;/b&gt;" in page.text
    assert "<b>partner</b>" not in page.text
    assert "Source A" in page.text


def test_lookup_page_shows_the_cap_like_the_cli(
    client: TestClient, logged_in: str, seeded: None
) -> None:
    # Two Sources: score 2, Tier medium, so the capped default ip-medium Output.
    page = client.get("/lookup", params={"q": "45.9.20.1"}).text
    assert "ip-medium (cap 25000)" in page


@pytest.mark.parametrize("value", ["192.168.1.10", "not a thing", "   "])
def test_lookup_page_is_friendly_about_bad_values(
    client: TestClient, logged_in: str, value: str
) -> None:
    page = client.get("/lookup", params={"q": value})
    assert page.status_code == 200
    assert "is not a public IP, CIDR or domain" in page.text


def test_lookup_page_without_query_shows_the_form(client: TestClient, logged_in: str) -> None:
    page = client.get("/lookup")
    assert page.status_code == 200
    assert 'name="q"' in page.text
    assert "is not a public IP" not in page.text


def test_lookup_page_needs_login(client: TestClient) -> None:
    response = client.get("/lookup", params={"q": "45.9.20.1"}, follow_redirects=False)
    assert response.status_code == 303


def test_api_lookup(client: TestClient, logged_in: str, seeded: None) -> None:
    body = client.get("/api/v1/lookup", params={"q": "45.9.20.1"}).json()
    assert body["value"] == "45.9.20.1"
    assert body["kind"] == "ip"
    assert body["score"] == 2
    assert [s["source_name"] for s in body["sightings"]] == ["Source A", "Source B"]
    assert body["allowlisted_by"] is None
    assert all(set(o) == {"name", "max_entries"} for o in body["eligible_outputs"])

    allowed = client.get("/api/v1/lookup", params={"q": "45.9.21.7"}).json()
    assert allowed["allowlisted_by"]["note"] == "our <b>partner</b>"
    assert allowed["eligible_outputs"] == []


def test_api_lookup_rejects_bad_values(client: TestClient, logged_in: str) -> None:
    response = client.get("/api/v1/lookup", params={"q": "10.0.0.1"})
    assert response.status_code == 400


def test_api_lookup_needs_login(client: TestClient) -> None:
    assert client.get("/api/v1/lookup", params={"q": "45.9.20.1"}).status_code == 401


def test_lookup_page_caps_the_query_length_like_the_api(client: TestClient, logged_in: str) -> None:
    long_value = "a" * 501 + ".example.com"  # 513 characters
    page = client.get("/lookup", params={"q": long_value})
    assert page.status_code == 200
    assert "too long" in page.text
    assert "512" in page.text
    assert client.get("/api/v1/lookup", params={"q": long_value}).status_code == 422
