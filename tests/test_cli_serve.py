# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from threatcull import cli

# Brief requires proving an explicit non-default host is passed through untouched;
# this is never a real bind (uvicorn.run is monkeypatched in every test below).
_EXPLICIT_HOST = "0.0.0.0"  # noqa: S104


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    # cli.py resolves `uvicorn.run` via module attribute lookup at call time, so
    # patching the shared `uvicorn` module object here reaches it too.
    monkeypatch.setattr(uvicorn, "run", fake_run)
    return captured


def test_serve_defaults_to_loopback_on_port_6969(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    assert captured_run["host"] == "127.0.0.1"
    assert captured_run["port"] == 6969
    assert captured_run["log_level"] == "info"


def test_serve_passes_through_an_explicit_host_and_port(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    argv = ["--data-dir", str(tmp_path), "serve", "--host", _EXPLICIT_HOST, "--port", "9999"]
    assert cli.main(argv) == cli.EXIT_OK
    assert captured_run["host"] == _EXPLICIT_HOST
    assert captured_run["port"] == 9999


def test_serve_never_defaults_to_a_non_loopback_host(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    cli.main(["--data-dir", str(tmp_path), "serve"])
    assert captured_run["host"] != _EXPLICIT_HOST
