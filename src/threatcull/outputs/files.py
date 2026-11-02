# SPDX-License-Identifier: AGPL-3.0-only
"""Where Outputs live on disk."""

from __future__ import annotations

import errno
import os
from pathlib import Path

from threatcull.store.outputs import OutputSpec

_EXTENSIONS = {
    "plain": "txt",
    "hosts": "txt",
    "adguard": "txt",
    "rpz": "rpz",
    "csv": "csv",
    "json": "json",
}


def output_path(out_dir: Path, spec: OutputSpec) -> Path:
    return out_dir / f"{spec.name}.{_EXTENSIONS[spec.format]}"


# fsync on a directory fails with these where the filesystem can't sync directories
# at all; any other error (EIO, ENOSPC, ...) means the sync really failed.
_SYNC_UNSUPPORTED = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP})


def sync_directory(path: Path) -> None:
    """Flush ``path``'s directory entries, so renames and new entries in it survive a power cut.

    A filesystem that can't sync a directory is skipped; any other failure raises,
    so a Compile never records Outputs as published when their entries may be lost.
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _SYNC_UNSUPPORTED:
            raise
    finally:
        os.close(fd)


def missing_directories(path: Path) -> list[Path]:
    """``path`` and its ancestors that don't exist yet, deepest first."""
    missing: list[Path] = []
    for candidate in (path, *path.parents):
        if candidate.exists():
            break
        missing.append(candidate)
    return missing
