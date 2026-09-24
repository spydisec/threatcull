# SPDX-License-Identifier: AGPL-3.0-only
import io
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from threatcull import cli
from threatcull.store.db import connect
from threatcull.store.users import count_users, verify_user

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
