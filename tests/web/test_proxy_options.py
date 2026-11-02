# SPDX-License-Identifier: AGPL-3.0-only
"""``--trusted-proxy``, ``--secure-cookies`` and bare-IP (homelab) hosts."""

from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from tests.web.conftest import ADMIN_PASSWORD, ADMIN_USER, csrf_from, login
from threatcull import cli
from threatcull.store.outputs import ensure_default_outputs
from threatcull.web.app import create_app
from threatcull.web.deps import open_db
from threatcull.web.security import ForwardedHeadersMiddleware, client_ip, parse_trusted_proxies

# Documentation ranges (RFC 5737), never real hosts.
CLIENT_A = "203.0.113.7"
CLIENT_B = "198.51.100.9"


def _client(
    data_dir: Path,
    *,
    peer: str,
    trusted: Sequence[str] = (),
    base_url: str = "http://testserver",
    secure_cookies: bool = False,
) -> TestClient:
    app = create_app(
        data_dir, start_scheduler=False, trusted_proxies=trusted, secure_cookies=secure_cookies
    )
    return TestClient(app, base_url=base_url, client=(peer, 50000))


def _post_login(client: TestClient, password: str, xff: str | None = None) -> int:
    headers = {"X-Forwarded-For": xff} if xff is not None else {}
    token = csrf_from(client.get("/login", headers=headers).text)
    response = client.post(
        "/login",
        data={"username": ADMIN_USER, "password": password, "csrf": token},
        headers=headers,
        follow_redirects=False,
    )
    status: int = response.status_code
    return status


# --- client_ip() ----------------------------------------------------------------


def _request(peer: str | None, xff: Sequence[str] = (), trusted: Sequence[str] = ()) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(trusted_proxies=parse_trusted_proxies(trusted)))
    scope: dict[str, Any] = {
        "type": "http",
        "headers": [(b"x-forwarded-for", value.encode()) for value in xff],
        "app": app,
        "client": (peer, 1234) if peer is not None else None,
    }
    return Request(scope)


def test_client_ip_ignores_forwarded_for_by_default() -> None:
    assert client_ip(_request("127.0.0.1", [CLIENT_A])) == "127.0.0.1"


def test_client_ip_ignores_forwarded_for_from_an_untrusted_peer() -> None:
    assert client_ip(_request(CLIENT_B, [CLIENT_A], trusted=["127.0.0.1"])) == CLIENT_B


def test_client_ip_uses_forwarded_for_from_a_trusted_peer() -> None:
    assert client_ip(_request("127.0.0.1", [CLIENT_A], trusted=["127.0.0.1"])) == CLIENT_A


def test_client_ip_takes_the_right_most_untrusted_address() -> None:
    # The client forged the left-most entry; the proxy appended the real peer.
    request = _request("127.0.0.1", [f"1.1.1.1, {CLIENT_A}"], trusted=["127.0.0.1"])
    assert client_ip(request) == CLIENT_A


def test_client_ip_skips_trusted_hops_given_as_a_cidr() -> None:
    request = _request("10.1.2.3", [f"1.1.1.1, {CLIENT_A}, 10.9.9.9"], trusted=["10.0.0.0/8"])
    assert client_ip(request) == CLIENT_A


def test_client_ip_joins_repeated_forwarded_for_headers() -> None:
    request = _request("127.0.0.1", ["1.1.1.1", CLIENT_A], trusted=["127.0.0.1"])
    assert client_ip(request) == CLIENT_A


def test_client_ip_handles_ipv6() -> None:
    request = _request("::1", ["2001:db8::5"], trusted=["::1"])
    assert client_ip(request) == "2001:db8::5"


def test_client_ip_falls_back_to_the_peer_on_a_garbage_hop() -> None:
    request = _request("127.0.0.1", [f"{CLIENT_A}, not-an-ip"], trusted=["127.0.0.1"])
    assert client_ip(request) == "127.0.0.1"


def test_client_ip_trusted_peer_without_header_is_the_peer() -> None:
    assert client_ip(_request("127.0.0.1", trusted=["127.0.0.1"])) == "127.0.0.1"


def test_client_ip_with_every_hop_trusted_is_the_left_most() -> None:
    request = _request("10.0.0.1", ["10.0.0.3, 10.0.0.2"], trusted=["10.0.0.0/8"])
    assert client_ip(request) == "10.0.0.3"


def test_client_ip_without_a_peer_is_unknown() -> None:
    assert client_ip(_request(None, [CLIENT_A], trusted=["127.0.0.1"])) == "unknown"


@pytest.mark.parametrize("bad", ["", "nope", "10.0.0.0/33", "300.1.1.1"])
def test_parse_trusted_proxies_rejects_bad_values(bad: str) -> None:
    with pytest.raises(ValueError, match="trusted proxy"):
        parse_trusted_proxies([bad])


def test_parse_trusted_proxies_accepts_ips_and_cidrs() -> None:
    parsed = parse_trusted_proxies(["127.0.0.1", "10.0.0.0/8", "::1", "192.168.1.1/24"])
    assert [str(n) for n in parsed] == ["127.0.0.1/32", "10.0.0.0/8", "::1/128", "192.168.1.0/24"]


# --- login rate limiter end to end ----------------------------------------------


def test_untrusted_client_cannot_dodge_the_limit_with_forwarded_for(
    tmp_path: Path, admin: str
) -> None:
    with _client(tmp_path, peer=CLIENT_B) as client:
        for i in range(5):
            assert _post_login(client, "wrong password!!", xff=f"10.0.0.{i}") == 401
        assert _post_login(client, "wrong password!!", xff="10.0.0.99") == 429


def test_trusted_proxy_makes_the_limiter_use_the_forwarded_address(
    tmp_path: Path, admin: str
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        for _ in range(5):
            assert _post_login(client, "wrong password!!", xff=CLIENT_A) == 401
        assert _post_login(client, "wrong password!!", xff=CLIENT_A) == 429
        # A different client behind the same proxy is not blocked.
        assert _post_login(client, ADMIN_PASSWORD, xff=CLIENT_B) == 303


def test_forging_the_left_most_hop_through_a_trusted_proxy_does_not_help(
    tmp_path: Path, admin: str
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        for i in range(5):
            assert _post_login(client, "wrong password!!", xff=f"10.0.0.{i}, {CLIENT_A}") == 401
        assert _post_login(client, "wrong password!!", xff=f"10.0.0.99, {CLIENT_A}") == 429


# --- --secure-cookies -------------------------------------------------------------


def _login_cookie(client: TestClient) -> str:
    token = csrf_from(client.get("/login").text)
    response = client.post(
        "/login",
        data={"username": ADMIN_USER, "password": ADMIN_PASSWORD, "csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    cookie: str = response.headers["set-cookie"].lower()
    return cookie


def test_session_cookie_is_not_secure_by_default(tmp_path: Path, admin: str) -> None:
    with _client(tmp_path, peer=CLIENT_A) as client:
        assert "secure" not in _login_cookie(client)


def test_secure_cookies_sets_the_secure_flag(tmp_path: Path, admin: str) -> None:
    with _client(
        tmp_path, peer=CLIENT_A, base_url="https://testserver", secure_cookies=True
    ) as client:
        cookie = _login_cookie(client)
    assert "; secure" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


# --- serve flags ----------------------------------------------------------------


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", ADMIN_PASSWORD)

    def fake_run(app: Any, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    return captured


def _session_https_only(app: Any) -> bool:
    [session] = [m for m in app.user_middleware if m.cls.__name__ == "SessionMiddleware"]
    https_only: bool = session.kwargs["https_only"]
    return https_only


def test_serve_defaults_to_plain_http_cookies_and_no_trusted_proxy(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    app = captured_run["app"]
    assert _session_https_only(app) is False
    assert app.state.trusted_proxies == ()
    # uvicorn's own X-Forwarded-For handling would bypass client_ip(); keep it off.
    assert captured_run["proxy_headers"] is False


def test_serve_passes_secure_cookies_and_trusted_proxies(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    argv = [
        "--data-dir",
        str(tmp_path),
        "serve",
        "--secure-cookies",
        "--trusted-proxy",
        "127.0.0.1",
        "--trusted-proxy",
        "10.0.0.0/8",
    ]
    assert cli.main(argv) == cli.EXIT_OK
    app = captured_run["app"]
    assert _session_https_only(app) is True
    assert [str(n) for n in app.state.trusted_proxies] == ["127.0.0.1/32", "10.0.0.0/8"]
    assert captured_run["proxy_headers"] is False


def test_serve_rejects_a_bad_trusted_proxy(
    tmp_path: Path, captured_run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--data-dir", str(tmp_path), "serve", "--trusted-proxy", "nope"])
    assert exc.value.code == 2
    assert "trusted proxy" in capsys.readouterr().err
    assert "app" not in captured_run


# --- homelab: bare IP hosts, plain HTTP, no host validation ------------------------


@pytest.fixture(params=["http://192.168.1.10:6969", "http://10.0.0.5"])
def lan_client(request: pytest.FixtureRequest, tmp_path: Path, admin: str) -> Iterator[TestClient]:
    conn = open_db(tmp_path)
    try:
        ensure_default_outputs(conn)
    finally:
        conn.close()
    with _client(tmp_path, peer=CLIENT_A, base_url=request.param) as client:
        yield client


def test_bare_ip_host_works_end_to_end(lan_client: TestClient, tmp_path: Path) -> None:
    base = str(lan_client.base_url).rstrip("/")
    csrf = login(lan_client)
    response = lan_client.post(
        "/allowlist", data={"csrf": csrf, "value": "1.2.3.4", "note": ""}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "1.2.3.4" in lan_client.get("/allowlist").text
    outputs = lan_client.get("/outputs").text
    assert f"{base}/o/" in outputs


# --- review round 1: more X-Forwarded-For shapes ------------------------------------


def test_client_ip_trailing_comma_leaves_an_empty_hop_so_the_peer_is_used() -> None:
    request = _request("127.0.0.1", [f"{CLIENT_A},"], trusted=["127.0.0.1"])
    assert client_ip(request) == "127.0.0.1"


@pytest.mark.parametrize(
    ("hop", "expected"),
    [
        ("[2001:db8::5]:1234", "2001:db8::5"),
        ("[2001:db8::5]", "2001:db8::5"),
        (f"{CLIENT_A}:5555", CLIENT_A),
        ("[2001:db8::5]junk", "127.0.0.1"),
        ("[2001:db8::5", "127.0.0.1"),
        (f"{CLIENT_A}:port", "127.0.0.1"),
    ],
)
def test_client_ip_reads_hops_with_ports(hop: str, expected: str) -> None:
    assert client_ip(_request("127.0.0.1", [hop], trusted=["127.0.0.1"])) == expected


def test_client_ip_long_chain_still_finds_the_right_most_untrusted_hop() -> None:
    hops = ", ".join(["1.1.1.1"] * 10_000 + [CLIENT_A])
    assert client_ip(_request("127.0.0.1", [hops], trusted=["127.0.0.1"])) == CLIENT_A


def test_client_ip_too_many_trusted_hops_falls_back_to_the_peer() -> None:
    hops = ", ".join([CLIENT_A] + ["10.0.0.2"] * 25)
    assert client_ip(_request("10.0.0.1", [hops], trusted=["10.0.0.0/8"])) == "10.0.0.1"


def test_client_ip_normalises_ipv4_mapped_ipv6() -> None:
    request = _request("::ffff:127.0.0.1", [f"::ffff:{CLIENT_A}"], trusted=["127.0.0.1"])
    assert client_ip(request) == CLIENT_A


@pytest.mark.parametrize("wide", ["0.0.0.0/0", "::/0", "10.0.0.0/7", "fc00::/15"])
def test_parse_trusted_proxies_rejects_too_wide_ranges(wide: str) -> None:
    with pytest.raises(ValueError, match="too wide"):
        parse_trusted_proxies([wide])


def test_parse_trusted_proxies_accepts_the_narrowest_allowed_ranges() -> None:
    assert len(parse_trusted_proxies(["10.0.0.0/8", "fc00::/16"])) == 2


def test_serve_rejects_a_too_wide_trusted_proxy(
    tmp_path: Path, captured_run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--data-dir", str(tmp_path), "serve", "--trusted-proxy", "0.0.0.0/0"])
    assert exc.value.code == 2
    assert "too wide" in capsys.readouterr().err
    assert "app" not in captured_run


# --- review round 1: X-Forwarded-Proto / X-Forwarded-Host -------------------------


@pytest.fixture
def outputs_ready(tmp_path: Path, admin: str) -> None:
    conn = open_db(tmp_path)
    try:
        ensure_default_outputs(conn)
    finally:
        conn.close()


def _outputs_page(client: TestClient, headers: dict[str, str]) -> str:
    login(client)
    page: str = client.get("/outputs", headers=headers).text
    return page


def test_trusted_proxy_https_proto_shows_https_feed_urls(
    tmp_path: Path, outputs_ready: None
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Proto": "https"})
    assert "https://testserver/o/" in page


def test_the_right_most_forwarded_proto_wins(tmp_path: Path, outputs_ready: None) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Proto": "http, HTTPS "})
    assert "https://testserver/o/" in page


def test_untrusted_peer_forwarded_proto_is_ignored(tmp_path: Path, outputs_ready: None) -> None:
    with _client(tmp_path, peer=CLIENT_B, trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Proto": "https"})
    assert "http://testserver/o/" in page
    assert "https://" not in page


def test_forwarded_proto_is_ignored_without_trusted_proxies(
    tmp_path: Path, outputs_ready: None
) -> None:
    with _client(tmp_path, peer="127.0.0.1") as client:
        app = client.app
        assert isinstance(app, FastAPI)
        installed: list[Any] = [m.cls for m in app.user_middleware]
        assert ForwardedHeadersMiddleware not in installed
        page = _outputs_page(client, {"X-Forwarded-Proto": "https"})
    assert "http://testserver/o/" in page


@pytest.mark.parametrize("proto", ["ftp", "https://evil", "", "httpss", "https;x"])
def test_garbage_forwarded_proto_is_ignored(
    tmp_path: Path, outputs_ready: None, proto: str
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Proto": proto})
    assert "http://testserver/o/" in page


@pytest.mark.parametrize("host", ["feeds.lan:8443", "[2001:db8::1]:8443", "10.0.0.5"])
def test_trusted_proxy_forwarded_host_is_used(
    tmp_path: Path, outputs_ready: None, host: str
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host})
    assert f"https://{host}/o/" in page


@pytest.mark.parametrize(
    "host", ["evil.example/x", "user@evil.example", "a b", "", "evil.example?x", "a\\b"]
)
def test_malformed_forwarded_host_is_ignored(
    tmp_path: Path, outputs_ready: None, host: str
) -> None:
    with _client(tmp_path, peer="127.0.0.1", trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Host": host})
    assert "http://testserver/o/" in page


def test_untrusted_peer_forwarded_host_is_ignored(tmp_path: Path, outputs_ready: None) -> None:
    with _client(tmp_path, peer=CLIENT_B, trusted=["127.0.0.1"]) as client:
        page = _outputs_page(client, {"X-Forwarded-Host": "evil.example"})
    assert "evil.example" not in page
