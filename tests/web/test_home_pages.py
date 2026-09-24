# SPDX-License-Identifier: AGPL-3.0-only
"""``/home`` (Home Network) pages, the ``/api/v1/home`` mirror and the dashboard banner."""

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
from threatcull.store.allowlist import AllowlistEntry
from threatcull.store.home import HomeEntry, add_home, home_entries
from threatcull.store.outputs import OutputSpec, create_output
from threatcull.store.runs import finish_run, start_run
from threatcull.store.sightings import record_fetch_success
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db

BANNER = "Your Home Network appears in upstream feeds"


def _entries(tmp_path: Path) -> list[HomeEntry]:
    conn = open_db(tmp_path)
    try:
        return home_entries(conn)
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


def test_home_page_redirects_to_login_when_logged_out(client: TestClient) -> None:
    response = client.get("/home", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_home_page_lists_entries_with_origin_badges(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    conn = open_db(tmp_path)
    try:
        add_home(conn, "45.9.20.1", "office", now=utcnow())
        add_home(conn, "45.9.20.2", "gateway", now=utcnow(), origin="auto")
    finally:
        conn.close()
    page = client.get("/home")
    assert page.status_code == 200
    assert "45.9.20.1" in page.text
    assert "office" in page.text
    assert 'class="badge badge-manual"' in page.text
    assert 'class="badge badge-auto"' in page.text
    assert "api.ipify.org" in page.text  # the public-IP button explains itself


def test_add_redirects_and_stores_manual(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/home",
        data={"csrf": logged_in, "value": " Home.Example.COM ", "note": "vpn"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/home"
    assert _entries(tmp_path) == [HomeEntry("home.example.com", "domain", "vpn", "manual")]


def test_add_private_is_400_with_explanation_and_escaped_input(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/home",
        data={"csrf": logged_in, "value": "192.168.1.10", "note": "<b>lan</b>"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "no Home Network entry is needed" in response.text
    assert "192.168.1.10" in response.text
    assert "<b>lan</b>" not in response.text
    assert "&lt;b&gt;lan&lt;/b&gt;" in response.text
    assert _entries(tmp_path) == []


def test_add_with_a_bogus_origin_is_400(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    response = client.post(
        "/home",
        data={"csrf": logged_in, "value": "45.9.20.1", "origin": "home"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert _entries(tmp_path) == []


def test_add_and_remove_need_csrf(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    refused = client.post("/home", data={"value": "45.9.20.1"}, follow_redirects=False)
    assert refused.status_code == 403
    assert _entries(tmp_path) == []
    client.post("/home", data={"csrf": logged_in, "value": "45.9.20.1"})
    refused = client.post("/home/remove", data={"value": "45.9.20.1"}, follow_redirects=False)
    assert refused.status_code == 403
    assert len(_entries(tmp_path)) == 1


def test_remove_redirects_and_unknown_is_404(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    client.post("/home", data={"csrf": logged_in, "value": "45.9.20.1"})
    response = client.post(
        "/home/remove", data={"csrf": logged_in, "value": "45.9.20.1"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert _entries(tmp_path) == []
    missing = client.post(
        "/home/remove", data={"csrf": logged_in, "value": "45.9.20.1"}, follow_redirects=False
    )
    assert missing.status_code == 404


def test_remove_invalid_value_is_400(client: TestClient, logged_in: str) -> None:
    response = client.post(
        "/home/remove", data={"csrf": logged_in, "value": "not a value"}, follow_redirects=False
    )
    assert response.status_code == 400
    assert "not a public IP" in response.text


def test_detect_public_ip_failure_is_shown(client: TestClient, logged_in: str) -> None:
    def offline(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("offline")

    client.app.state.public_ip_fetcher_factory = lambda: offline  # type: ignore[attr-defined]
    response = client.post("/home/detect-public", data={"csrf": logged_in})
    assert response.status_code == 200
    assert "Could not learn the public IP" in response.text


def test_detect_needs_csrf(
    client: TestClient, logged_in: str, detector: _Detector, public: _PublicFetcher
) -> None:
    assert client.post("/home/detect", follow_redirects=False).status_code == 403
    assert client.post("/home/detect-public", follow_redirects=False).status_code == 403
    assert detector.calls == []
    assert public.urls == []


def test_detect_shows_candidates_and_adds_nothing(
    client: TestClient,
    logged_in: str,
    tmp_path: Path,
    detector: _Detector,
    public: _PublicFetcher,
) -> None:
    client.post("/home", data={"csrf": logged_in, "value": "45.9.22.0/24"})
    response = client.post("/home/detect", data={"csrf": logged_in})
    assert response.status_code == 200
    assert "default gateway (eth0)" in response.text
    assert response.text.count('name="origin" value="auto"') == 2  # one Add per candidate
    assert detector.calls == [(["45.9.22.0/24"], ["testserver"])]
    assert public.urls == []  # plain Detect never calls out
    assert [e.value for e in _entries(tmp_path)] == ["45.9.22.0/24"]


def test_candidate_add_is_stored_as_auto(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    response = client.post(
        "/home",
        data={
            "csrf": logged_in,
            "value": "45.9.20.1",
            "note": "default gateway (eth0)",
            "origin": "auto",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _entries(tmp_path) == [HomeEntry("45.9.20.1", "ip", "default gateway (eth0)", "auto")]


def test_detect_public_ip_calls_out_only_on_its_own_button(
    client: TestClient, logged_in: str, tmp_path: Path, public: _PublicFetcher
) -> None:
    response = client.post("/home/detect-public", data={"csrf": logged_in})
    assert response.status_code == 200
    assert public.urls == ["https://api.ipify.org"]
    assert "45.9.20.99" in response.text
    assert _entries(tmp_path) == []


# --- API mirror --------------------------------------------------------------------


def test_api_home_is_401_when_logged_out(client: TestClient) -> None:
    assert client.get("/api/v1/home").status_code == 401


def test_api_home_crud(client: TestClient, logged_in: str, tmp_path: Path) -> None:
    headers = {"X-CSRF-Token": logged_in}
    assert client.post("/api/v1/home", json={"value": "45.9.20.1"}).status_code == 403
    created = client.post(
        "/api/v1/home", json={"value": "45.9.20.1", "note": "office"}, headers=headers
    )
    assert created.status_code == 200
    assert created.json() == {
        "value": "45.9.20.1",
        "kind": "ip",
        "note": "office",
        "origin": "manual",
    }
    private = client.post("/api/v1/home", json={"value": "10.0.0.1"}, headers=headers)
    assert private.status_code == 400
    assert "no Home Network entry is needed" in private.json()["detail"]
    assert client.get("/api/v1/home").json() == [created.json()]
    assert client.delete("/api/v1/home", params={"value": "45.9.20.1"}).status_code == 403
    removed = client.delete("/api/v1/home", params={"value": "45.9.20.1"}, headers=headers)
    assert removed.json() == {"value": "45.9.20.1", "removed": True}
    missing = client.delete("/api/v1/home", params={"value": "45.9.20.1"}, headers=headers)
    assert missing.status_code == 404


def test_api_detect(
    client: TestClient, logged_in: str, detector: _Detector, public: _PublicFetcher
) -> None:
    headers = {"X-CSRF-Token": logged_in}
    assert client.post("/api/v1/home/detect").status_code == 403
    body = client.post("/api/v1/home/detect", headers=headers).json()
    assert body == {
        "candidates": [
            {"value": "45.9.20.1", "reason": "default gateway (eth0)"},
            {"value": "45.9.21.53", "reason": "DNS resolver in /etc/resolv.conf"},
        ]
    }
    assert public.urls == []
    body = client.post("/api/v1/home/detect", params={"public_ip": "true"}, headers=headers).json()
    assert {"value": "45.9.20.99", "reason": "public IP reported by api.ipify.org"} in body[
        "candidates"
    ]
    assert public.urls == ["https://api.ipify.org"]


# --- dashboard banner ----------------------------------------------------------------


def _compile_with_home(tmp_path: Path, *, listed: bool) -> None:
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
        add_home(conn, "45.9.20.1" if listed else "45.9.30.1", now=now)
        compile_outputs(conn, tmp_path / "outputs", now=now)
    finally:
        conn.close()


def test_dashboard_banner_only_when_the_last_compile_had_hits(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    assert BANNER not in client.get("/").text
    _compile_with_home(tmp_path, listed=False)
    assert BANNER not in client.get("/").text
    _compile_with_home(tmp_path, listed=True)
    page = client.get("/").text
    assert BANNER in page
    assert "45.9.20.1" in page
    assert "Feed A" in page


def test_dashboard_banner_survives_a_later_failed_compile(
    client: TestClient, logged_in: str, tmp_path: Path
) -> None:
    """A failed Compile records no hits; the banner must not go dark behind it."""
    _compile_with_home(tmp_path, listed=False)
    _compile_with_home(tmp_path, listed=True)
    page = client.get("/").text
    assert BANNER in page
    assert "45.9.20.1" in page

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
