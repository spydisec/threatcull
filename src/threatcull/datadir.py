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
    Missing parent directories are created with the usual umask. Raises
    ``DataDirError`` (one line with the ``chown`` fix) when the directory cannot be
    created or written, typically a bind mount Docker created as root.
    """
    try:
        path.mkdir(mode=PRIVATE_MODE, parents=True)
    except FileExistsError:
        pass
    except PermissionError as exc:
        # A missing directory whose parent this process cannot write.
        raise DataDirError(
            f"cannot create data directory {path}: {exc.strerror}; create it and "
            f"run chown {os.getuid()}:{os.getgid()} {path} on the host"
        ) from None
    else:
        path.chmod(PRIVATE_MODE)  # mkdir's mode is masked by the umask
        return
    # Writability first: a root-owned bind mount is an error, not a loose-mode warning.
    if not os.access(path, os.W_OK | os.X_OK):
        uid, gid = os.getuid(), os.getgid()
        raise DataDirError(
            f"data directory {path} is not writable by uid {uid}: "
            f"run chown {uid}:{gid} {path} on the host"
        )
    mode = path.stat().st_mode
    if mode & _OTHERS_BITS:
        log.warning(
            "data directory %s is readable by other users (mode %o); "
            "consider chmod 700: it holds the database and the session secret",
            path,
            mode & 0o777,
        )
