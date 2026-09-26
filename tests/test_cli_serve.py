# SPDX-License-Identifier: AGPL-3.0-only
import logging
import re
from pathlib import Path
from typing import Any

import pytest
import uvicorn
import yaml

from threatcull import cli
from threatcull.store.db import connect
from threatcull.store.outputs import list_outputs
from threatcull.store.sources import list_sources
from threatcull.store.users import verify_user
from threatcull.web.routes.feeds import FeedTokenAccessFilter

# Brief requires proving an explicit non-default host is passed through untouched;
# this is never a real bind (uvicorn.run is monkeypatched in every test below).
_EXPLICIT_HOST = "0.0.0.0"  # noqa: S104


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    # serve refuses to start with no users; let it bootstrap the admin account.
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", "correct horse battery")

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


def test_serve_refuses_an_unknown_tz(
    tmp_path: Path,
    captured_run: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("TZ", "Melbourne")
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_ERROR
    assert "Australia/Melbourne" in capsys.readouterr().err
    assert "app" not in captured_run


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


def test_serve_installs_the_feed_token_access_log_filter(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    logger = logging.getLogger("uvicorn.access")
    for existing in list(logger.filters):
        if isinstance(existing, FeedTokenAccessFilter):
            logger.removeFilter(existing)
    try:
        assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
        installed = [f for f in logger.filters if isinstance(f, FeedTokenAccessFilter)]
        assert len(installed) == 1
    finally:
        for existing in list(logger.filters):
            if isinstance(existing, FeedTokenAccessFilter):
                logger.removeFilter(existing)


def _catalog_file(path: Path, ids: list[str], *, disabled: tuple[str, ...] = ()) -> Path:
    entries = [
        {
            "id": source_id,
            "name": f"Source {source_id}",
            "url": f"https://{source_id}.example/list.txt",
            "format": "plain",
            "kind": "ip",
            "category": "malicious",
            "licence_class": "permissive",
            "business_use": "allowed",
            "licence": "MIT",
            "licence_url": "https://example.com/l",
            "refresh_minutes": 60,
            "default_enabled": source_id not in disabled,
        }
        for source_id in ids
    ]
    path.write_text(yaml.safe_dump({"sources": entries}), encoding="utf-8")
    return path


_TOKEN_SHAPED = re.compile(r"[A-Za-z0-9_-]{43}")


def _enabled(data_dir: Path) -> dict[str, bool]:
    conn = connect(data_dir / "threatcull.db")
    try:
        return {s.id: s.enabled for s in list_sources(conn)}
    finally:
        conn.close()


def test_serve_syncs_the_catalog_and_creates_default_outputs_without_printing_tokens(
    tmp_path: Path, captured_run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    catalog = _catalog_file(tmp_path / "catalog.yaml", ["a", "b"])
    data_dir = tmp_path / "data"
    assert cli.main(["--data-dir", str(data_dir), "--catalog", str(catalog), "serve"]) == 0
    out = capsys.readouterr()
    assert _enabled(data_dir) == {"a": True, "b": True}
    assert "rotate their tokens on the Outputs page" in out.out
    assert not _TOKEN_SHAPED.search(out.out + out.err)
    conn = connect(data_dir / "threatcull.db")
    try:
        assert {spec.name for spec in list_outputs(conn)} >= {"ip-high", "domains-malicious"}
    finally:
        conn.close()


def test_serve_on_an_upgraded_catalog_keeps_the_operator_choices(
    tmp_path: Path, captured_run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    old = _catalog_file(tmp_path / "old.yaml", ["a", "b"])
    assert cli.main(["--data-dir", str(data_dir), "--catalog", str(old), "init"]) == 0
    disable = ["--data-dir", str(data_dir), "--catalog", str(old), "sources", "disable", "a"]
    assert cli.main(disable) == 0
    capsys.readouterr()
    new = _catalog_file(tmp_path / "new.yaml", ["a", "b", "c"])
    assert cli.main(["--data-dir", str(data_dir), "--catalog", str(new), "serve"]) == 0
    assert _enabled(data_dir) == {"a": False, "b": True, "c": True}
    assert "Default Outputs created" not in capsys.readouterr().out


def test_serve_creates_the_admin_from_a_password_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    captured_run: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = tmp_path / "admin.txt"
    secret.write_text("from the file\n")
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD_FILE", str(secret))  # wins over the env var
    data_dir = tmp_path / "data"
    assert cli.main(["--data-dir", str(data_dir), "serve"]) == 0
    assert "created user admin from THREATCULL_ADMIN_PASSWORD_FILE" in capsys.readouterr().out
    conn = connect(data_dir / "threatcull.db")
    try:
        assert verify_user(conn, "admin", "from the file")
        assert not verify_user(conn, "admin", "correct horse battery")
    finally:
        conn.close()


def test_serve_with_a_missing_password_file_fails_on_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD_FILE", str(tmp_path / "missing.txt"))
    assert cli.main(["--data-dir", str(tmp_path / "data"), "serve"]) == 1
    err = capsys.readouterr().err.strip()
    assert "THREATCULL_ADMIN_PASSWORD_FILE" in err
    assert "\n" not in err


def test_an_upgrade_keeps_tokens_and_the_secret_and_adds_default_disabled_sources(
    tmp_path: Path, captured_run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    old = _catalog_file(tmp_path / "old.yaml", ["a"])
    assert cli.main(["--data-dir", str(data_dir), "--catalog", str(old), "serve"]) == 0
    secret = (data_dir / "secret.key").read_bytes()
    conn = connect(data_dir / "threatcull.db")
    try:
        hashes = dict(conn.execute("SELECT name, feed_token_hash FROM outputs").fetchall())
    finally:
        conn.close()

    new = _catalog_file(tmp_path / "new.yaml", ["a", "late"], disabled=("late",))
    assert cli.main(["--data-dir", str(data_dir), "--catalog", str(new), "serve"]) == 0

    assert _enabled(data_dir) == {"a": True, "late": False}
    assert (data_dir / "secret.key").read_bytes() == secret
    conn = connect(data_dir / "threatcull.db")
    try:
        assert dict(conn.execute("SELECT name, feed_token_hash FROM outputs").fetchall()) == hashes
    finally:
        conn.close()
