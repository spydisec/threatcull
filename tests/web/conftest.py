# SPDX-License-Identifier: AGPL-3.0-only
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatcull.web.app import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(tmp_path, start_scheduler=False)
    with TestClient(app) as test_client:
        yield test_client
