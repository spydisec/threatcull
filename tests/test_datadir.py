# SPDX-License-Identifier: AGPL-3.0-only
"""The data directory: private (0700) when ThreatCull creates it, a warning otherwise."""

import logging
import os
from pathlib import Path

import pytest

from threatcull import cli
from threatcull.datadir import ensure_data_dir
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
