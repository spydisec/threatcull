# SPDX-License-Identifier: AGPL-3.0-only
"""Where Outputs live on disk."""

from __future__ import annotations

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


def sync_directory(path: Path) -> None:
    """Flush ``path``'s directory entries, so renames inside it survive a power cut.

    Best effort: a filesystem that can't sync a directory leaves the renames to the
    kernel's own writeback, as before.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
