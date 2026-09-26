# SPDX-License-Identifier: AGPL-3.0-only
"""Allowlist entries flagged as your network: the page, Detect, the API and the dashboard alert."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.clock import utcnow
from threatcull.compiling import compile_outputs
from threatcull.fetcher import FetchError, FetchResult
from threatcull.home_detect import Candidate
from threatcull.indicators import Indicator
from threatcull.store.allowlist import AllowlistEntry, add_entry, operator_entries
from threatcull.store.outputs import OutputSpec, create_output
from threatcull.store.runs import finish_run, start_run
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db

BANNER = "Your own network appears in upstream feeds"


def _entries(tmp_path: Path) -> list[tuple[str, str, bool]]:
    conn = open_db(tmp_path)
    try:
        return [(e.value, e.note, e.mine) for e in operator_entries(conn)]
    finally:
        conn.close()


class _Detector:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], list[str]]] = []

    def __call__(
        self, *, existing: Sequence[AllowlistEntry] = (), extra_hosts: Iterable[str] = ()
    ) -> list[Candidate]:
        self.calls.append(([e.value for e in existing], list(extra_hosts)))
        return [
            Candidate("45.9.20.1", "default gateway (eth0)"),
            Candidate("45.9.21.53", "DNS resolver in /etc/resolv.conf"),
        ]


class _PublicFetcher:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.urls.append(url)
        return FetchResult("ok", "45.9.20.99")


@pytest.fixture
def detector(client: TestClient) -> _Detector:
    fake = _Detector()
    client.app.state.home_detector = fake  # type: ignore[attr-defined]
    return fake


@pytest.fixture
def public(client: TestClient) -> _PublicFetcher:
    fake = _PublicFetcher()
    client.app.state.public_ip_fetcher_factory = lambda: fake  # type: ignore[attr-defined]
    return fake


# --- HTML page -------------------------------------------------------------------


def test_the_home_network_page_is_gone(client: TestClient, logged_in: str) -> None:
    assert client.get("/home").status_code == 404
    assert 'href="/home"' not in client.get("/allowlist").text


def test_add_as_my_network_and_switch_the_flag(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist",
        data={"csrf": logged_in, "value": " Shop.Example.COM ", "note": "vpn", "mine": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _entries(tmp_path) == [("shop.example.com", "vpn", True)]
    page = client.get("/allowlist").text
    assert "my network</span>" in page
    assert "Not my network" in page

    client.post("/allowlist/mine", data={"csrf": logged_in, "value": "shop.example.com"})
    assert _entries(tmp_path) == [("shop.example.com", "vpn", False)]
    missing = client.post(
        "/allowlist/mine",
        data={"csrf": logged_in, "value": "45.9.20.1", "mine": "true"},
        follow_redirects=False,
    )
    assert missing.status_code == 404


def test_add_private_is_400_with_explanation_and_escaped_input(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/allowlist",
        data={"csrf": logged_in, "value": "192.168.1.10", "note": "<b>lan</b>", "mine": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "no allowlist entry is needed" in response.text
    assert "<b>lan</b>" not in response.text
    assert "&lt;b&gt;lan&lt;/b&gt;" in response.text
    assert _entries(tmp_path) == []


def test_the_flag_needs_csrf(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    client.post("/allowlist", data={"csrf": logged_in, "value": "45.9.20.1"})
    refused = client.post(
        "/allowlist/mine", data={"value": "45.9.20.1", "mine": "true"}, follow_redirects=False
    )
    assert refused.status_code == 403
    assert _entries(tmp_path) == [("45.9.20.1", "", False)]


def test_detect_public_ip_failure_is_shown(client: TestClient, logged_in: str) -> None:
    def offline(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("offline")

    client.app.state.public_ip_fetcher_factory = lambda: offline  # type: ignore[attr-defined]
    response = client.post("/allowlist/detect-public", data={"csrf": logged_in})
    assert response.status_code == 200
    assert "Could not learn the public IP" in response.text


def test_detect_needs_csrf(
    client: TestClient, logged_in: str, detector: _Detector, public: _PublicFetcher
) -> None:
    assert client.post("/allowlist/detect", follow_redirects=False).status_code == 403
    assert client.post("/allowlist/detect-public", follow_redirects=False).status_code == 403
    assert detector.calls == []
    assert public.urls == []


def test_detect_shows_candidates_and_adds_nothing(
    client: TestClient,
    logged_in: str,
    tmp_path: Path,
    detector: _Detector,
    public: _PublicFetcher,
) -> None:
    client.post("/allowlist", data={"csrf": logged_in, "value": "45.9.22.0/24"})
    response = client.post("/allowlist/detect", data={"csrf": logged_in})
    assert response.status_code == 200
    assert "default gateway (eth0)" in response.text
    assert response.text.count("Add as my network") == 2  # one Add per candidate
    assert detector.calls == [(["45.9.22.0/24"], ["testserver"])]
    assert public.urls == []  # plain Detect never calls out
    assert [value for value, _, _ in _entries(tmp_path)] == ["45.9.22.0/24"]


def test_detect_public_ip_calls_out_only_on_its_own_button(
    client: TestClient, logged_in: str, tmp_path: Path, public: _PublicFetcher
) -> None:
    response = client.post("/allowlist/detect-public", data={"csrf": logged_in})
    assert response.status_code == 200
    assert public.urls == ["https://api.ipify.org"]
    assert "45.9.20.99" in response.text
    assert _entries(tmp_path) == []


def test_import_as_my_network(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    response = client.post(
        "/allowlist/import",
        data={"csrf": logged_in, "mine": "true"},
        files={"file": ("mine.txt", b"45.9.20.1  # office\n192.168.1.10\n", "text/plain")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get("/allowlist").text
    assert "Imported 1 new entry" in page
    assert "1 line skipped" in page
    assert _entries(tmp_path) == [("45.9.20.1", "office", True)]


# --- API ---------------------------------------------------------------------------


def test_api_allowlist_carries_the_flag(client: TestClient, logged_in: str) -> None:
    headers = {"X-CSRF-Token": logged_in}
    created = client.post(
        "/api/v1/allowlist",
        json={"value": "45.9.20.1", "note": "office", "mine": True},
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json() == {
        "value": "45.9.20.1",
        "kind": "ip",
        "note": "office",
        "origin": "operator",
        "mine": True,
    }
    private = client.post("/api/v1/allowlist", json={"value": "10.0.0.1"}, headers=headers)
    assert private.status_code == 400
    assert "no allowlist entry is needed" in private.json()["detail"]
    assert client.get("/api/v1/home").status_code == 404


def test_api_detect(
    client: TestClient, logged_in: str, detector: _Detector, public: _PublicFetcher
) -> None:
    headers = {"X-CSRF-Token": logged_in}
    assert client.post("/api/v1/allowlist/detect").status_code == 403
    body = client.post("/api/v1/allowlist/detect", headers=headers).json()
    assert body == {
        "candidates": [
            {"value": "45.9.20.1", "reason": "default gateway (eth0)"},
            {"value": "45.9.21.53", "reason": "DNS resolver in /etc/resolv.conf"},
        ]
    }
    assert public.urls == []
    body = client.post(
        "/api/v1/allowlist/detect", params={"public_ip": "true"}, headers=headers
    ).json()
    assert {"value": "45.9.20.99", "reason": "public IP reported by api.ipify.org"} in body[
        "candidates"
    ]
    assert public.urls == ["https://api.ipify.org"]


# --- dashboard alert -----------------------------------------------------------------


def _compile_with_mine(tmp_path: Path, *, listed: bool) -> None:
    conn = open_db(tmp_path)
    try:
        now = utcnow()
        if not listed:
            sync_catalog(conn, [make_entry(id="feed-a", name="Feed A", default_enabled=True)])
            create_output(
                conn, OutputSpec("ips", "ip", frozenset({"malicious"}), "low", None, "plain")
            )
            record_fetch_success(
                conn,
                "feed-a",
                {Indicator("45.9.20.1", "ip")},
                now=now,
                etag=None,
                last_modified=None,
            )
        add_entry(conn, "45.9.20.1" if listed else "45.9.30.1", mine=True, now=now)
        compile_outputs(conn, tmp_path / "outputs", now=now)
    finally:
        conn.close()


def test_dashboard_alert_only_when_the_last_compile_had_hits(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert BANNER not in client.get("/").text
    _compile_with_mine(tmp_path, listed=False)
    assert BANNER not in client.get("/").text
    _compile_with_mine(tmp_path, listed=True)
    page = client.get("/").text
    assert BANNER in page
    assert "45.9.20.1" in page
    assert "Feed A" in page


def test_dashboard_alert_survives_a_later_failed_compile(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    """A failed Compile records no hits; the alert must not go dark behind it."""
    _compile_with_mine(tmp_path, listed=False)
    _compile_with_mine(tmp_path, listed=True)
    conn = open_db(tmp_path)
    try:
        later = utcnow()
        run_id = start_run(conn, "compile", now=later)
        finish_run(conn, run_id, "failed", now=later, error="boom")
    finally:
        conn.close()
    page = client.get("/").text
    assert BANNER in page
    assert "45.9.20.1" in page
