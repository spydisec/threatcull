# SPDX-License-Identifier: AGPL-3.0-only
"""The data directory: private (0700) when ThreatCull creates it, a warning otherwise."""

import logging
import multiprocessing
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from threatcull import cli
from threatcull.backup import restore_backup
from threatcull.datadir import (
    LOCK_NAME,
    DataDirError,
    DataDirLocked,
    data_dir_lock,
    database_lock,
    ensure_data_dir,
)
from threatcull.web.app import create_app


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_a_new_data_dir_is_created_0700_even_with_a_loose_umask(tmp_path: Path) -> None:
    target = tmp_path / "a" / "data"
    old = os.umask(0o002)
    try:
        ensure_data_dir(target)
    finally:
        os.umask(old)
    assert _mode(target) == 0o700


def test_an_existing_dir_is_never_chmodded_but_a_loose_one_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "data"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    with caplog.at_level(logging.WARNING, logger="threatcull.datadir"):
        ensure_data_dir(target)
    assert _mode(target) == 0o755
    assert "readable by other users" in caplog.text
    assert str(target) in caplog.text


def test_a_private_existing_dir_is_quiet(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    target = tmp_path / "data"
    target.mkdir(mode=0o700)
    with caplog.at_level(logging.WARNING, logger="threatcull.datadir"):
        ensure_data_dir(target)
    assert caplog.text == ""


def test_the_cli_creates_its_data_dir_0700(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    assert cli.main(["--data-dir", str(target), "outputs", "list"]) == cli.EXIT_OK
    assert _mode(target) == 0o700


def test_create_app_creates_its_data_dir_0700(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    create_app(target, start_scheduler=False)
    assert _mode(target) == 0o700


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_a_data_dir_the_process_cannot_write_is_a_clear_error(tmp_path: Path) -> None:
    target = tmp_path / "data"
    target.mkdir(mode=0o500)
    try:
        with pytest.raises(DataDirError, match=r"not writable by uid \d+: run chown"):
            ensure_data_dir(target)
    finally:
        target.chmod(0o700)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_the_cli_reports_an_unwritable_data_dir_on_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "data"
    target.mkdir(mode=0o500)
    try:
        assert cli.main(["--data-dir", str(target), "outputs", "list"]) == 1
    finally:
        target.chmod(0o700)
    err = capsys.readouterr().err.strip()
    assert err.startswith("error: data directory")
    assert "chown" in err
    assert "\n" not in err


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_an_unwritable_dir_reports_the_error_without_the_loose_mode_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "data"
    target.mkdir(mode=0o555)  # like a root-owned 0755 bind mount: readable, not writable
    try:
        with caplog.at_level(logging.WARNING), pytest.raises(DataDirError):
            ensure_data_dir(target)
    finally:
        target.chmod(0o700)
    assert "readable by other users" not in caplog.text


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_a_missing_dir_under_an_unwritable_parent_is_a_clear_error(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o500)
    try:
        with pytest.raises(DataDirError, match=r"cannot create data directory .*chown"):
            ensure_data_dir(parent / "data")
    finally:
        parent.chmod(0o700)


# --- data directory lock -------------------------------------------------------------
# flock locks belong to the open file description, so a second open in the SAME process
# may or may not conflict. Exclusivity is therefore proven with a real second process.


def _hold_lock(path: str, ready: Any, release: Any) -> None:
    with data_dir_lock(Path(path)):
        ready.set()
        release.wait(30)


def test_lock_is_exclusive_across_processes(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold_lock, args=(str(tmp_path), ready, release))
    child.start()
    try:
        assert ready.wait(30)
        with (
            pytest.raises(DataDirLocked, match=r"ThreatCull is running on .*: stop it first"),
            data_dir_lock(tmp_path),
        ):
            pass
    finally:
        release.set()
        child.join(30)
    with data_dir_lock(tmp_path):  # released when the holder exits
        pass


def test_leftover_lock_file_does_not_block(tmp_path: Path) -> None:
    (tmp_path / LOCK_NAME).write_text("")
    with data_dir_lock(tmp_path):
        pass


def test_lock_file_is_private(tmp_path: Path) -> None:
    with data_dir_lock(tmp_path):
        assert _mode(tmp_path / LOCK_NAME) == 0o600


def test_an_unopenable_lock_file_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real_open = os.open

    def deny_lock(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path).endswith(LOCK_NAME):
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_lock)
    assert cli.main(["--data-dir", str(tmp_path), "run"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert err == f"error: cannot open the lock file {tmp_path / LOCK_NAME}: Permission denied\n"


def test_run_refuses_while_another_process_holds_the_lock(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold_lock, args=(str(tmp_path), ready, release))
    child.start()
    try:
        assert ready.wait(30)
        assert cli.main(["--data-dir", str(tmp_path), "run"]) == cli.EXIT_ERROR
    finally:
        release.set()
        child.join(30)
    assert re.search(r"ThreatCull is running on .*: stop it first", capsys.readouterr().err)


# --- database-access lock ----------------------------------------------------------------


def _hold_db_lock(path: str, exclusive: bool, ready: Any, release: Any) -> None:
    with database_lock(Path(path), exclusive=exclusive):
        ready.set()
        release.wait(30)


def _in_child(tmp_path: Path, exclusive: bool) -> tuple[Any, Any, Any]:
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold_db_lock, args=(str(tmp_path), exclusive, ready, release))
    child.start()
    assert ready.wait(30)
    return child, ready, release


def test_shared_database_holders_coexist(tmp_path: Path) -> None:
    child, _, release = _in_child(tmp_path, exclusive=False)
    try:
        with database_lock(tmp_path, exclusive=False):
            pass
    finally:
        release.set()
        child.join(30)


def test_restore_refuses_while_a_command_uses_the_database(tmp_path: Path) -> None:
    child, _, release = _in_child(tmp_path, exclusive=False)
    try:
        with pytest.raises(DataDirLocked, match="using the database"):
            restore_backup(tmp_path, tmp_path / "missing.db", now=datetime.now(UTC))
    finally:
        release.set()
        child.join(30)


def test_commands_refuse_while_a_restore_holds_the_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    child, _, release = _in_child(tmp_path, exclusive=True)
    try:
        assert cli.main(["--data-dir", str(tmp_path), "outputs", "list"]) == cli.EXIT_ERROR
        assert cli.main(["--data-dir", str(tmp_path), "backup", "create"]) == cli.EXIT_ERROR
    finally:
        release.set()
        child.join(30)
    err = capsys.readouterr().err
    assert err.count("a restore is running") == 2
