# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end: the whole pipeline driven through the browser UI, offline.

Mirrors ``tests/integration/test_offline_pipeline.py``'s fixture HTTP server and
socket guard, but exercises the web UI instead of the CLI: create an admin,
log in, add and enable Custom Sources, "Run now" and wait for the runner
(bounded, never a real sleep), rotate a Feed Token, fetch the published
Output, look the value up, allowlist it, and confirm the next Compile drops
it (the Shrink Guard blocks the 100% drop; a forced Compile publishes it).
"""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.fixture_server import FixtureServer
from tests.web.conftest import csrf_from, login
from threatcull.store.outputs import ensure_default_outputs
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner

WAIT = 10.0
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_TOKEN_URL = re.compile(r"/o/ip-high\?token=([A-Za-z0-9_-]+)")
_LAST_COMPILE_STATUS = re.compile(r'<dd id="last-compile-status">([^<]*)</dd>')


def _last_compile_status(client: TestClient) -> str:
    """The Status value in the dashboard's "Last Compile" card."""
    match = _LAST_COMPILE_STATUS.search(client.get("/").text)
    assert match is not None, "no Last Compile status on the dashboard"
    return match.group(1).strip()


@pytest.fixture
def no_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every non-loopback ``connect()`` raises: the whole flow below must stay offline."""
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOOPBACK:
            raise AssertionError(f"test tried to reach the internet: {address!r}")
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


def _runner(client: TestClient) -> PipelineRunner:
    runner = client.app.state.runner  # type: ignore[attr-defined]
    assert isinstance(runner, PipelineRunner)
    return runner


def _add_and_enable_source(client: TestClient, csrf: str, source_id: str, url: str) -> None:
    """Add a Custom Source through the Sources page form, then enable it."""
    added = client.post(
        "/sources/custom",
        data={
            "csrf": csrf,
            "id": source_id,
            "name": source_id,
            "url": url,
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
            "business_use": "allowed",
        },
        follow_redirects=False,
    )
    assert added.status_code == 303, added.text
    enabled = client.post(
        f"/sources/{source_id}/enable", data={"csrf": csrf}, follow_redirects=False
    )
    assert enabled.status_code == 303, enabled.text


def test_end_to_end_browser_flow(
    no_internet: None,
    fixture_server: FixtureServer,
    client: TestClient,
    admin: str,
    tmp_path: Path,
) -> None:
    conn = open_db(tmp_path)
    try:
        ensure_default_outputs(conn)  # includes ip-high, the Output this test publishes to
    finally:
        conn.close()

    csrf = login(client, admin)
    target_ip = "45.9.20.1"

    # Three independent Custom Sources (each its own Source Family) so the shared IP
    # earns Confidence Score 3: enough to reach Tier high and land in ip-high.
    for name in ("a", "b", "c"):
        fixture_server.add(f"/{name}.txt", (200, f"{target_ip}\n".encode(), {}))
        _add_and_enable_source(client, csrf, f"custom-{name}", fixture_server.url(f"/{name}.txt"))
        csrf = csrf_from(client.get("/sources").text)

    # -- Run now: Fetch every enabled Source, then Compile. Wait bounded, not a real sleep.
    started = client.post("/runs/now", data={"csrf": csrf}, follow_redirects=False)
    assert started.status_code == 303
    assert started.headers["location"] == "/runs"
    runner = _runner(client)
    assert runner.wait(WAIT)
    first_result = runner.last_result
    assert first_result is not None
    assert first_result.status == "ok"
    assert _last_compile_status(client) == "ok"

    # -- Rotate the Feed Token on ip-high through the UI.
    csrf = csrf_from(client.get("/outputs").text)
    rotated = client.post("/outputs/ip-high/rotate", data={"csrf": csrf}, follow_redirects=False)
    assert rotated.status_code == 200
    match = _TOKEN_URL.search(rotated.text)
    assert match is not None, rotated.text
    token = match.group(1)

    # -- Fetch the published feed with the new token: the IP is there.
    fed = client.get("/o/ip-high", params={"token": token})
    assert fed.status_code == 200
    assert target_ip in fed.text.splitlines()

    # -- Lookup explains it: the Score/Tier, the Sources that listed it, the eligible Output.
    lookup_page = client.get("/lookup", params={"q": target_ip}).text
    assert target_ip in lookup_page
    assert "score 3 (high)" in lookup_page
    assert "ip-high" in lookup_page
    assert "custom-a" in lookup_page

    # -- Allowlist the IP, then run again: dropping the only entry of ip-high is a
    # 100% shrink, so the Shrink Guard must block; then force a Compile past it.
    csrf = csrf_from(client.get("/allowlist").text)
    added_entry = client.post(
        "/allowlist",
        data={"csrf": csrf, "value": target_ip, "note": "false positive"},
        follow_redirects=False,
    )
    assert added_entry.status_code == 303

    csrf = csrf_from(client.get("/").text)
    run_again = client.post("/runs/now", data={"csrf": csrf}, follow_redirects=False)
    assert run_again.status_code == 303
    assert runner.wait(WAIT)
    second_result = runner.last_result
    assert second_result is not None
    assert second_result.status == "blocked"
    assert _last_compile_status(client) == "blocked"
    # Blocked means the previous Output is kept: the IP is still served.
    kept = client.get("/o/ip-high", params={"token": token})
    assert target_ip in kept.text.splitlines()

    csrf = csrf_from(client.get("/runs").text)
    forced = client.post(
        "/runs/compile-force",
        data={"csrf": csrf, "confirm": "true"},
        follow_redirects=False,
    )
    assert forced.status_code == 303
    assert runner.wait(WAIT)
    forced_result = runner.last_result
    assert forced_result is not None
    assert forced_result.status == "ok"
    assert _last_compile_status(client) == "ok"

    # -- The Output no longer contains the now-allowlisted IP.
    fed_again = client.get("/o/ip-high", params={"token": token})
    assert fed_again.status_code == 200
    assert target_ip not in fed_again.text.splitlines()
