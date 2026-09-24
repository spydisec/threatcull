# SPDX-License-Identifier: AGPL-3.0-only
"""The whole pipeline over HTTP with every non-loopback connection forbidden."""

import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.fixture_server import FixtureServer
from threatcull.cli import main

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture
def no_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOOPBACK:
            raise AssertionError(f"test tried to reach the internet: {address!r}")
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


def _catalog(tmp_path: Path, server: FixtureServer) -> Path:
    def entry(id_: str, path: str, **extra: Any) -> dict[str, Any]:
        return {
            "id": id_,
            "name": id_.title(),
            "url": server.url(path),
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
            "licence_class": "permissive",
            "business_use": "allowed",
            "licence": "MIT",
            "licence_url": "https://example.com/l",
            "refresh_minutes": 60,
            "default_enabled": True,
            **extra,
        }

    sources = [
        entry("ip-one", "/ip1.txt"),
        entry("ip-two", "/ip2.txt"),
        entry("ip-three", "/ip3.csv", format="csv", category="c2"),
        entry("dom-one", "/dom1.txt", kind="domain", format="hosts"),
        entry("dom-two", "/dom2.txt", kind="domain", format="adblock", category="phishing"),
        entry(
            "cdn",
            "/cdn.json",
            format="json",
            json_keys=["addresses"],
            role="allowlist",
            category="infrastructure",
            business_use="unknown",
        ),
    ]
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({"sources": sources}), encoding="utf-8")
    return path


def test_offline_pipeline_end_to_end(
    no_internet: None,
    fixture_server: FixtureServer,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ok = {"ETag": '"v1"'}
    fixture_server.add("/ip1.txt", (200, b"# feed\n45.9.20.1\n45.9.20.2\n104.16.1.1\n", ok))
    fixture_server.add("/ip2.txt", (200, b"45.9.20.1\n45.9.20.2\n10.0.0.1\n", ok))
    fixture_server.add("/ip3.csv", (200, b"#ip,ioc\n45.9.20.1,Sliver\n", ok))
    fixture_server.add("/dom1.txt", (200, b"0.0.0.0 evil.example.com\n", ok))
    fixture_server.add("/dom2.txt", (200, b"||evil.example.com^\n||phish.example.net^\n", ok))
    fixture_server.add("/cdn.json", (200, b'{"addresses": ["104.16.0.0/13"]}', ok))
    catalog = _catalog(tmp_path, fixture_server)
    cli = ["--data-dir", str(tmp_path / "data"), "--catalog", str(catalog)]

    assert main([*cli, "run"]) == 0
    out_dir = tmp_path / "data" / "outputs"

    def body(name: str) -> list[str]:
        return [ln for ln in (out_dir / name).read_text().splitlines() if not ln.startswith("#")]

    assert body("ip-high.txt") == ["45.9.20.1"]
    assert body("ip-medium.txt") == ["45.9.20.1", "45.9.20.2"]
    assert body("domains-malicious.txt") == ["evil.example.com", "phish.example.net"]

    capsys.readouterr()
    assert main([*cli, "lookup", "104.16.1.1"]) == 0
    assert "allowlisted by 104.16.0.0/13" in capsys.readouterr().out

    # Second run: conditional requests are sent; one upstream now serves an HTML error page.
    fixture_server.add("/ip2.txt", (200, b"<html>rate limited</html>\n", {}))
    assert main([*cli, "run"]) == 0
    assert fixture_server.routes["/ip1.txt"].request_headers[-1]["If-None-Match"] == '"v1"'
    assert body("ip-medium.txt") == ["45.9.20.1", "45.9.20.2"]
