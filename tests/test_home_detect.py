# SPDX-License-Identifier: AGPL-3.0-only
"""Home Network auto-detect: local files only, public IP only on request."""

from pathlib import Path

import httpx
import pytest

from threatcull import home_detect
from threatcull.fetcher import FetchError, FetchResult
from threatcull.home_detect import (
    IPIFY_URL,
    PUBLIC_IP_TIMEOUT,
    Candidate,
    DetectPaths,
    _public_ip_client,
    default_gateways,
    detect_candidates,
    detect_public_ip,
    local_addresses,
    public_ip_candidate,
    public_ip_fetcher,
    resolvers,
)
from threatcull.store.allowlist import AllowlistEntry

# 45.9.20.1 is 2D.09.14.01; /proc/net/route stores it little-endian as 0114092D.
ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0114092D\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0014092D\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
)
RESOLV = (
    "# written by a tool\n"
    "nameserver 45.9.21.53\n"
    "nameserver 127.0.0.53\n"
    "nameserver fe80::1%eth0\n"
    "nameserver 2a01:4f8::53\n"
    "search example.com\n"
)
FIB_TRIE = (
    "Main:\n"
    "  +-- 0.0.0.0/0 3 0 5\n"
    "     |-- 0.0.0.0\n"
    "        /0 universe UNICAST\n"
    "     |-- 45.9.20.5\n"
    "        /32 host LOCAL\n"
    "     |-- 192.168.1.20\n"
    "        /32 host LOCAL\n"
    "Local:\n"
    "  +-- 0.0.0.0/0 3 0 5\n"
    "     |-- 45.9.20.5\n"
    "        /32 host LOCAL\n"
)
IF_INET6 = (
    "2a0104f8000000000000000000000005 02 40 00 00     eth0\n"
    "00000000000000000000000000000001 01 80 10 80       lo\n"
    "fe800000000000000000000000000001 02 40 20 80     eth0\n"
)


@pytest.fixture
def paths(tmp_path: Path) -> DetectPaths:
    files = {"route": ROUTE, "resolv": RESOLV, "fib_trie": FIB_TRIE, "if_inet6": IF_INET6}
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return DetectPaths(
        route=tmp_path / "route",
        resolv=tmp_path / "resolv",
        fib_trie=tmp_path / "fib_trie",
        if_inet6=tmp_path / "if_inet6",
    )


def test_gateway_hex_is_little_endian(paths: DetectPaths) -> None:
    assert default_gateways(paths.route) == [("45.9.20.1", "eth0"), ("192.168.1.1", "wlan0")]


def test_resolvers_skip_comments_and_zone_ids(paths: DetectPaths) -> None:
    assert resolvers(paths.resolv) == ["45.9.21.53", "127.0.0.53", "fe80::1", "2a01:4f8::53"]


def test_local_addresses_from_proc(paths: DetectPaths) -> None:
    assert local_addresses(paths) == ["45.9.20.5", "192.168.1.20", "2a01:4f8::5", "::1", "fe80::1"]


def test_detect_returns_only_new_public_values(paths: DetectPaths) -> None:
    existing = [AllowlistEntry("45.9.21.0/24", "cidr", "Home Network", "home")]
    found = detect_candidates(
        existing=existing, extra_hosts=["45.9.22.1", "localhost"], paths=paths
    )
    assert found == [
        Candidate("45.9.20.5", "address of this host"),
        Candidate("2a01:4f8::5", "address of this host"),
        Candidate("45.9.22.1", "address this server is reached at"),
        Candidate("45.9.20.1", "default gateway (eth0)"),
        Candidate("2a01:4f8::53", "DNS resolver in /etc/resolv.conf"),
    ]


def test_detect_uses_an_injected_host_resolver(paths: DetectPaths) -> None:
    found = detect_candidates(paths=paths, host_addresses=lambda: ["45.9.23.4", "10.1.1.1"])
    assert Candidate("45.9.23.4", "address of this host") in found
    assert Candidate("45.9.20.5", "address of this host") not in found


def test_missing_files_are_skipped_silently(tmp_path: Path) -> None:
    missing = DetectPaths(
        route=tmp_path / "no-route",
        resolv=tmp_path / "no-resolv",
        fib_trie=tmp_path / "no-fib",
        if_inet6=tmp_path / "no-inet6",
    )
    assert detect_candidates(paths=missing) == []


class _Fetcher:
    def __init__(self, text: str = "", error: Exception | None = None) -> None:
        self.text = text
        self.error = error
        self.urls: list[str] = []

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        return FetchResult("ok", self.text)


def test_public_ip_is_validated() -> None:
    fetcher = _Fetcher("45.9.20.99\n")
    assert detect_public_ip(fetcher) == "45.9.20.99"
    assert fetcher.urls == [IPIFY_URL]
    assert IPIFY_URL == "https://api.ipify.org"


@pytest.mark.parametrize(
    "text", ["192.168.1.1", "<html>hi</html>", "45.9.20.1 45.9.20.2", "", "45.9.20.0/24", "x.com"]
)
def test_public_ip_rejects_anything_but_one_public_address(text: str) -> None:
    assert detect_public_ip(_Fetcher(text)) is None


def test_public_ip_failure_is_none() -> None:
    assert detect_public_ip(_Fetcher(error=FetchError("offline"))) is None


def test_malformed_proc_lines_are_skipped(tmp_path: Path) -> None:
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\n"
        "eth0\t00000000\n"
        "eth0\t00000000\tZZZZZZZZ\t0003\n"
        "eth0\t00000000\t0114092D\t0001\n",  # no RTF_GATEWAY flag
        encoding="utf-8",
    )
    inet6 = tmp_path / "if_inet6"
    inet6.write_text("\nshort 01 40 00 00 eth0\n" + "z" * 32 + " 01 40 00 00 eth0\n")
    assert default_gateways(route) == []
    paths = DetectPaths(route=route, resolv=route, fib_trie=tmp_path / "none", if_inet6=inet6)
    assert local_addresses(paths) == []


def test_public_ip_client_is_short_and_does_not_follow_redirects() -> None:
    client = _public_ip_client()  # building it sends nothing
    try:
        assert client.timeout.read == PUBLIC_IP_TIMEOUT
        assert client.follow_redirects is False
    finally:
        client.close()


def test_public_ip_fetcher_closes_its_client_after_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="45.9.20.99")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(home_detect, "_public_ip_client", lambda: client)
    fetcher = public_ip_fetcher()
    assert detect_public_ip(fetcher) == "45.9.20.99"
    assert client.is_closed


def test_public_ip_fetcher_closes_its_client_even_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(home_detect, "_public_ip_client", lambda: client)
    fetcher = public_ip_fetcher()
    assert detect_public_ip(fetcher) is None
    assert client.is_closed


def test_public_ip_candidate_skips_known_and_covered_addresses() -> None:
    covered = [AllowlistEntry("45.9.20.0/24", "cidr", "Home Network", "home")]
    assert public_ip_candidate(_Fetcher("45.9.20.99"), existing=covered) == ("45.9.20.99", None)
    found = [Candidate("45.9.21.1", "address of this host")]
    assert public_ip_candidate(_Fetcher("45.9.21.1"), found=found) == ("45.9.21.1", None)
    assert public_ip_candidate(_Fetcher("45.9.21.2")) == (
        "45.9.21.2",
        Candidate("45.9.21.2", "public IP reported by api.ipify.org"),
    )
    assert public_ip_candidate(_Fetcher(error=FetchError("offline"))) == (None, None)
