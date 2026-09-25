# SPDX-License-Identifier: AGPL-3.0-only
"""The data directory: holds the database, the session secret and the Outputs."""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

PRIVATE_MODE = 0o700
_OTHERS_BITS = 0o077


class DataDirError(Exception):
    """The data directory exists but this process cannot use it (one line for the operator)."""


def ensure_data_dir(path: Path) -> None:
    """Create ``path`` with mode 0700 if missing; warn if an existing one is open to others.

    A directory the operator chose and created stays as it is (never
    chmodded); ThreatCull only says when group or other users can get in.
    Missing parent directories are created with the usual umask.
    """
    try:
        path.mkdir(mode=PRIVATE_MODE, parents=True)
    except FileExistsError:
        mode = path.stat().st_mode
        if mode & _OTHERS_BITS:
            log.warning(
                "data directory %s is readable by other users (mode %o); "
                "consider chmod 700: it holds the database and the session secret",
                path,
                mode & 0o777,
            )
        if not os.access(path, os.W_OK | os.X_OK):
            # Typically a bind mount Docker created as root for a non-root container.
            uid, gid = os.getuid(), os.getgid()
            raise DataDirError(
                f"data directory {path} is not writable by uid {uid}: "
                f"run chown {uid}:{gid} {path} on the host"
            ) from None
        return
    path.chmod(PRIVATE_MODE)  # mkdir's mode is masked by the umask
