# SPDX-License-Identifier: AGPL-3.0-only
import io
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient

from tests.web.conftest import login
from threatcull import cli
from threatcull.clock import utcnow
from threatcull.store.db import connect
from threatcull.store.runs import recent_runs, start_run
from threatcull.store.users import count_users, verify_user
from threatcull.web.app import create_app

PASSWORD = "correct horse battery"  # noqa: S105 - test-only credential


@pytest.fixture(autouse=True)
def _no_admin_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATCULL_ADMIN_PASSWORD", raising=False)


def _user_ok(tmp_path: Path, username: str, password: str) -> bool:
    conn = connect(tmp_path / cli.DB_NAME)
    try:
        return verify_user(conn, username, password)
    finally:
        conn.close()


def _count(tmp_path: Path) -> int:
    conn = connect(tmp_path / cli.DB_NAME)
    try:
        return count_users(conn)
    finally:
        conn.close()


# --- user create ----------------------------------------------------------------


def test_user_create_reads_one_line_from_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\nignored second line\n"))
    argv = ["--data-dir", str(tmp_path), "user", "create", "alice", "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_OK
    assert "created user alice" in capsys.readouterr().out
    assert _user_ok(tmp_path, "alice", PASSWORD)


def test_user_create_prompts_twice_with_getpass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return PASSWORD

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    assert cli.main(["--data-dir", str(tmp_path), "user", "create", "bob"]) == cli.EXIT_OK
    assert len(prompts) == 2
    assert "created user bob" in capsys.readouterr().out
    assert _user_ok(tmp_path, "bob", PASSWORD)


def test_user_create_rejects_mismatched_prompts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter([PASSWORD, PASSWORD + "x"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["--data-dir", str(tmp_path), "user", "create", "bob"]) == cli.EXIT_ERROR
    assert "do not match" in capsys.readouterr().err
    assert _count(tmp_path) == 0


def test_user_create_reports_rule_violations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    argv = ["--data-dir", str(tmp_path), "user", "create", "alice", "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_ERROR
    assert "12 characters" in capsys.readouterr().err
    assert _count(tmp_path) == 0


def test_user_create_reports_a_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--data-dir", str(tmp_path), "user", "create", "alice", "--password-stdin"]
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(argv) == cli.EXIT_OK
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(argv) == cli.EXIT_ERROR
    assert "already exists" in capsys.readouterr().err


# --- user set-password / list -------------------------------------------------


NEW_PASSWORD = "a brand new passphrase"  # noqa: S105 - test-only credential


def _create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, username: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    argv = ["--data-dir", str(tmp_path), "user", "create", username, "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_OK


def test_user_set_password_from_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _create(tmp_path, monkeypatch, "alice")
    monkeypatch.setattr("sys.stdin", io.StringIO(NEW_PASSWORD + "\n"))
    argv = ["--data-dir", str(tmp_path), "user", "set-password", "alice", "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_OK
    assert "password changed for alice" in capsys.readouterr().out
    assert _user_ok(tmp_path, "alice", NEW_PASSWORD)
    assert not _user_ok(tmp_path, "alice", PASSWORD)


def test_user_set_password_prompts_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _create(tmp_path, monkeypatch, "alice")
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return NEW_PASSWORD

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    assert cli.main(["--data-dir", str(tmp_path), "user", "set-password", "alice"]) == 0
    assert len(prompts) == 2
    assert _user_ok(tmp_path, "alice", NEW_PASSWORD)


def test_user_set_password_for_an_unknown_user_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(NEW_PASSWORD + "\n"))
    argv = ["--data-dir", str(tmp_path), "user", "set-password", "nobody", "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_ERROR
    assert "nobody" in capsys.readouterr().err


def test_user_set_password_enforces_the_password_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _create(tmp_path, monkeypatch, "alice")
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    argv = ["--data-dir", str(tmp_path), "user", "set-password", "alice", "--password-stdin"]
    assert cli.main(argv) == cli.EXIT_ERROR
    assert "12 characters" in capsys.readouterr().err
    assert _user_ok(tmp_path, "alice", PASSWORD)


def test_user_set_password_ends_existing_web_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _create(tmp_path, monkeypatch, "admin")
    with TestClient(create_app(tmp_path, start_scheduler=False)) as client:
        login(client, "admin", PASSWORD)
        assert client.get("/api/v1/me").status_code == 200
        monkeypatch.setattr("sys.stdin", io.StringIO(NEW_PASSWORD + "\n"))
        argv = ["--data-dir", str(tmp_path), "user", "set-password", "admin", "--password-stdin"]
        assert cli.main(argv) == cli.EXIT_OK
        assert client.get("/api/v1/me").status_code == 401


def test_user_list_shows_usernames_never_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _create(tmp_path, monkeypatch, "bob")
    _create(tmp_path, monkeypatch, "alice")
    capsys.readouterr()
    assert cli.main(["--data-dir", str(tmp_path), "user", "list"]) == cli.EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[0] for line in lines] == ["alice", "bob"]
    assert all("created=" in line for line in lines)
    assert "argon2" not in "\n".join(lines)


def test_user_list_with_no_users(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "user", "list"]) == cli.EXIT_OK
    assert "no web UI users" in capsys.readouterr().out


# --- serve bootstrap ------------------------------------------------------------


@pytest.fixture
def run_calls(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    calls: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(app))
    return calls


def test_serve_with_no_users_and_no_env_exits_1_with_guidance(
    tmp_path: Path, run_calls: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_ERROR
    assert run_calls == []
    assert "threatcull user create" in capsys.readouterr().err


def test_serve_creates_admin_from_the_env_var(
    tmp_path: Path, run_calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", PASSWORD)
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    assert len(run_calls) == 1
    assert _user_ok(tmp_path, "admin", PASSWORD)


def test_serve_ignores_the_env_var_once_users_exist(
    tmp_path: Path,
    run_calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    cli.main(["--data-dir", str(tmp_path), "user", "create", "alice", "--password-stdin"])
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", "another long password")
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    assert len(run_calls) == 1
    assert _count(tmp_path) == 1


def test_serve_rejects_a_weak_env_password(
    tmp_path: Path,
    run_calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", "short")
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_ERROR
    assert run_calls == []
    assert "12 characters" in capsys.readouterr().err


def test_serve_marks_runs_left_running_as_interrupted(
    tmp_path: Path, run_calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _create(tmp_path, monkeypatch, "alice")
    conn = connect(tmp_path / cli.DB_NAME)
    try:
        start_run(conn, "compile", now=utcnow())
    finally:
        conn.close()
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    conn = connect(tmp_path / cli.DB_NAME)
    try:
        (run,) = recent_runs(conn, 5)
    finally:
        conn.close()
    assert (run.status, run.error) == ("failed", "interrupted by restart")
    assert run.finished_at is not None


def test_serve_never_prints_feed_tokens(
    tmp_path: Path,
    run_calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``serve`` output lands in journald / container logs: no Feed Token there."""
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", PASSWORD)
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert "Feed Token" not in captured.out + captured.err
    assert "Default Outputs created; rotate their tokens on the Outputs page" in captured.out
    assert "threatcull outputs rotate-token" in captured.out


def test_serve_on_an_initialised_dir_says_nothing_about_outputs(
    tmp_path: Path,
    run_calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "init"]) == cli.EXIT_OK
    monkeypatch.setenv("THREATCULL_ADMIN_PASSWORD", PASSWORD)
    capsys.readouterr()
    assert cli.main(["--data-dir", str(tmp_path), "serve"]) == cli.EXIT_OK
    assert "Default Outputs" not in capsys.readouterr().out


def test_init_still_prints_the_feed_tokens(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--data-dir", str(tmp_path), "init"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert out.count("Feed Token for Output") == 5
