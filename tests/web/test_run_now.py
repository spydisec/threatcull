# SPDX-License-Identifier: AGPL-3.0-only
"""Run now / force Compile from the UI: single-flight, PRG flash messages."""

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from threatcull.fetcher import FetchResult
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.sources import sync_catalog
from threatcull.web.deps import open_db
from threatcull.web.jobs import PipelineRunner

WAIT = 10.0


class BlockingFetcher:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        self.entered.set()
        self.release.wait(WAIT)
        return FetchResult("ok", "45.9.20.1\n")


@pytest.fixture
def fake(client: TestClient, tmp_path: Path) -> Iterator[BlockingFetcher]:
    conn = open_db(tmp_path)
    try:
        sync_catalog(
            conn,
            [make_entry(id="a", url="https://a.example/1", default_enabled=True, name="Source A")],
        )
        ensure_default_outputs(conn)
    finally:
        conn.close()
    fetcher = BlockingFetcher()
    runner = PipelineRunner(tmp_path, fetcher_factory=lambda: fetcher)
    client.app.state.runner = runner  # type: ignore[attr-defined]
    yield fetcher
    fetcher.release.set()
    assert runner.wait(WAIT)


def _runner(client: TestClient) -> PipelineRunner:
    runner = client.app.state.runner  # type: ignore[attr-defined]
    assert isinstance(runner, PipelineRunner)
    return runner


def test_create_app_builds_one_runner(client: TestClient) -> None:
    assert isinstance(client.app.state.runner, PipelineRunner)  # type: ignore[attr-defined]


def test_run_now_twice_reports_already_running(
    client: TestClient, logged_in: str, fake: BlockingFetcher
) -> None:
    first = client.post("/runs/now", data={"csrf": logged_in}, follow_redirects=False)
    assert first.status_code == 303
    assert first.headers["location"] == "/runs"
    assert "Run started" in client.get("/runs").text
    assert fake.entered.wait(WAIT)

    second = client.post("/runs/now", data={"csrf": logged_in}, follow_redirects=False)
    assert second.status_code == 303
    page = client.get("/runs").text
    assert "A run is already in progress" in page
    assert "Run started" not in page  # the flash is one-shot

    # While running the dashboard shows it, and the status fragment keeps polling.
    assert "Running" in client.get("/").text
    fragment = client.get("/partials/status").text
    assert "Running" in fragment
    assert 'hx-trigger="every 3s"' in fragment

    fake.release.set()
    assert _runner(client).wait(WAIT)
    assert _runner(client).last_result is not None
    assert _runner(client).last_result.status == "ok"  # type: ignore[union-attr]
    idle = client.get("/partials/status").text
    assert "hx-trigger" not in idle
    assert "Running" not in idle
    assert "A run is already in progress" not in client.get("/runs").text


def test_run_now_needs_csrf(client: TestClient, logged_in: str, fake: BlockingFetcher) -> None:
    response = client.post("/runs/now", data={"csrf": "stale"}, follow_redirects=False)
    assert response.status_code == 403
    assert not _runner(client).is_running()
    assert not fake.entered.is_set()


def test_run_now_needs_login(client: TestClient, fake: BlockingFetcher) -> None:
    response = client.post("/runs/now", follow_redirects=False)
    assert response.status_code in (303, 403)
    assert not _runner(client).is_running()


def test_status_fragment_needs_login(client: TestClient) -> None:
    response = client.get("/partials/status", follow_redirects=False)
    assert response.status_code == 303


def test_force_compile_requires_the_confirm_checkbox(
    client: TestClient, logged_in: str, fake: BlockingFetcher
) -> None:
    response = client.post("/runs/compile-force", data={"csrf": logged_in})
    assert response.status_code == 400
    assert "confirm" in response.text.lower()
    assert _runner(client).last_result is None

    done = client.post(
        "/runs/compile-force",
        data={"csrf": logged_in, "confirm": "true"},
        follow_redirects=False,
    )
    assert done.status_code == 303
    assert "Compile forced" in client.get("/runs").text
    result = _runner(client).last_result
    assert result is not None
    assert result.status == "ok"
    assert not fake.entered.is_set()  # Compile only: no Fetch


def test_force_compile_while_running_reports_already_running(
    client: TestClient, logged_in: str, fake: BlockingFetcher
) -> None:
    client.post("/runs/now", data={"csrf": logged_in}, follow_redirects=False)
    assert fake.entered.wait(WAIT)
    forced = client.post(
        "/runs/compile-force",
        data={"csrf": logged_in, "confirm": "true"},
        follow_redirects=False,
    )
    assert forced.status_code == 303
    assert "A run is already in progress" in client.get("/runs").text
