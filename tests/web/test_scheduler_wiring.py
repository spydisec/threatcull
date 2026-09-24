# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduler in the app: started by the lifespan only when asked, rescanned on change."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_entry
from tests.web.conftest import login
from threatcull.store.outputs import ensure_default_outputs
from threatcull.store.sources import sync_catalog
from threatcull.web.app import create_app
from threatcull.web.deps import open_db
from threatcull.web.scheduler import Scheduler, fetch_job_id


@pytest.fixture
def seeded(tmp_path: Path) -> None:
    conn = open_db(tmp_path)
    try:
        sync_catalog(
            conn,
            [
                make_entry(id="a", url="https://a.example/1", default_enabled=True, name="A"),
                make_entry(id="c", url="https://c.example/1", default_enabled=False, name="C"),
            ],
        )
        ensure_default_outputs(conn)
    finally:
        conn.close()


@pytest.fixture
def scheduled_client(tmp_path: Path, seeded: None) -> Iterator[TestClient]:
    app = create_app(tmp_path, start_scheduler=True)
    with TestClient(app) as test_client:
        scheduler = _scheduler(test_client)
        yield test_client
    assert not scheduler.scheduler.running  # shut down with the app
    assert app.state.scheduler is None


def _scheduler(client: TestClient) -> Scheduler:
    scheduler = client.app.state.scheduler  # type: ignore[attr-defined]
    assert isinstance(scheduler, Scheduler)
    return scheduler


def test_create_app_without_scheduler_starts_none(client: TestClient) -> None:
    assert client.app.state.scheduler is None  # type: ignore[attr-defined]


def test_lifespan_starts_the_scheduler_and_scans_sources(scheduled_client: TestClient) -> None:
    scheduler = _scheduler(scheduled_client)
    assert scheduler.scheduler.running
    assert scheduler.scheduler.get_job(fetch_job_id("a")) is not None
    assert scheduler.scheduler.get_job(fetch_job_id("c")) is None
    assert scheduled_client.app.state.on_sources_changed == scheduler.rescan  # type: ignore[attr-defined]


def test_enabling_a_source_in_the_ui_adds_its_job(scheduled_client: TestClient, admin: str) -> None:
    token = login(scheduled_client)
    response = scheduled_client.post(
        "/sources/c/enable",
        data={"csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    scheduler = _scheduler(scheduled_client)
    assert scheduler.scheduler.get_job(fetch_job_id("c")) is not None

    response = scheduled_client.post(
        "/sources/a/disable",
        data={"csrf": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert scheduler.scheduler.get_job(fetch_job_id("a")) is None


def test_dashboard_shows_next_compile(scheduled_client: TestClient, admin: str) -> None:
    login(scheduled_client)
    page = scheduled_client.get("/").text
    assert "Next compile at" in page


def test_dashboard_without_scheduler_says_so(client: TestClient, logged_in: str) -> None:
    page = client.get("/").text
    assert "Next compile at" not in page
    assert "Scheduler is off" in page
