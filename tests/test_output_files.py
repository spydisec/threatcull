# SPDX-License-Identifier: AGPL-3.0-only
import errno
import os
from pathlib import Path

import pytest

from threatcull.outputs.files import sync_directory


def _failing_fsync(code: int) -> object:
    def fsync(fd: int) -> None:
        raise OSError(code, os.strerror(code))

    return fsync


@pytest.mark.parametrize("code", [errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP])
def test_a_filesystem_that_cannot_sync_directories_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(os, "fsync", _failing_fsync(code))
    sync_directory(tmp_path)


def test_a_real_fsync_failure_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "fsync", _failing_fsync(errno.EIO))
    with pytest.raises(OSError, match=os.strerror(errno.EIO)) as raised:
        sync_directory(tmp_path)
    assert raised.value.errno == errno.EIO


def test_a_directory_that_cannot_be_opened_propagates(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sync_directory(tmp_path / "missing")
