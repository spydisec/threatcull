# SPDX-License-Identifier: AGPL-3.0-only
"""Full database backups: an online copy, a check, and a lock-guarded restore.

``create_backup`` is safe while ThreatCull runs (SQLite's online backup API reads a
consistent snapshot). ``restore_backup`` needs ThreatCull stopped: it holds the
data-directory lock for its whole run, so ``serve`` and ``run`` cannot start under it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from threatcull.datadir import DATABASE_FILES, PRIVATE_MODE, data_dir_lock
from threatcull.outputs.files import sync_directory
from threatcull.store.db import BUSY_TIMEOUT_S, SCHEMA_VERSION

BACKUPS_DIRNAME = "backups"
FILE_MODE = 0o600
DB_NAME, *SIDECARS = DATABASE_FILES
RESTORE_TMP_NAME = f".{DB_NAME}.restore.tmp"
_STAMP = "%Y%m%dT%H%M%SZ"
_COPY_CHUNK = 1 << 20


class BackupError(Exception):
    """A backup or restore step failed (one line for the operator)."""


@dataclass(frozen=True)
class RestoreReport:
    safety_copy: Path | None  # None when the data directory had no database
    schema: int  # the restored file's user_version


def default_backup_path(data_dir: Path, *, prefix: str = "threatcull", now: datetime) -> Path:
    """``<data-dir>/backups/<prefix>-YYYYMMDDTHHMMSSZ.db`` in UTC."""
    stamp = now.astimezone(UTC).strftime(_STAMP)
    return data_dir / BACKUPS_DIRNAME / f"{prefix}-{stamp}.db"


def ensure_backups_dir(data_dir: Path) -> Path:
    """Create ``<data-dir>/backups`` with mode 0700 if missing; an existing one stays as it is."""
    path = data_dir / BACKUPS_DIRNAME
    try:
        path.mkdir(mode=PRIVATE_MODE)
    except FileExistsError:
        return path
    except OSError as exc:
        raise BackupError(f"cannot create {path}: {exc.strerror}") from None
    path.chmod(PRIVATE_MODE)  # mkdir's mode is masked by the umask
    return path


def create_backup(db_path: Path, dest: Path) -> Path:
    """Copy the database at ``db_path`` to ``dest`` (a new file, mode 0600) and return ``dest``.

    The copy goes to a hidden temp name in ``dest``'s folder, passes ``integrity_check``,
    is fsynced and only then renamed into place. Refuses an existing ``dest`` and a
    missing folder; any failure deletes the temp file and raises ``BackupError``.
    """
    if not db_path.is_file():
        raise BackupError(f"no database at {db_path}: nothing to back up")
    if not dest.parent.is_dir():
        raise BackupError(f"folder {dest.parent} does not exist")
    _refuse_existing(dest)
    tmp = dest.with_name(f".{dest.name}.tmp")
    try:
        # O_EXCL: never write through a leftover file or symlink; 0600 from the first byte.
        os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE))
    except FileExistsError:
        raise BackupError(
            f"{tmp} exists: another backup to {dest} is running, or one was interrupted "
            "(delete the file if no backup is running)"
        ) from None
    except OSError as exc:
        raise BackupError(f"cannot write {tmp}: {exc.strerror}") from None
    try:
        _online_copy(db_path, tmp)
        with _open_read_only(tmp) as conn:
            _require_integrity(conn, tmp)
        tmp.chmod(FILE_MODE)
        _fsync_file(tmp)
        _refuse_existing(dest)  # it may have appeared while copying
        tmp.rename(dest)
        sync_directory(dest.parent)
    except (sqlite3.Error, OSError) as exc:
        tmp.unlink(missing_ok=True)
        raise BackupError(f"backup of {db_path} failed: {exc}") from exc
    except BaseException:  # BackupError, KeyboardInterrupt: no half-written file stays
        tmp.unlink(missing_ok=True)
        raise
    return dest


def _refuse_existing(dest: Path) -> None:
    if dest.exists() or dest.is_symlink():
        raise BackupError(f"{dest} already exists; refusing to overwrite it")


def check_backup(path: Path) -> int:
    """Return the ``user_version`` of the backup at ``path`` after checking it.

    Raises ``BackupError`` unless the file is an intact SQLite database with the
    ThreatCull tables and a schema this version understands. Opens the file read-only
    and immutable, so a check never creates files next to it.
    """
    if not path.is_file():
        raise BackupError(f"{path} is not a file")
    wal = path.with_name(f"{path.name}-wal")
    if wal.is_file() and wal.stat().st_size > 0:
        raise BackupError(
            f"{wal} exists next to the backup and may hold changes the file lacks: "
            "use a copy made with `threatcull backup create`"
        )
    try:
        with _open_read_only(path) as conn:
            try:
                version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            except sqlite3.DatabaseError:
                raise BackupError(f"{path} is not a SQLite database") from None
            _require_integrity(conn, path)
            has_sources = conn.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'sources'"
            ).fetchone()
    except sqlite3.Error as exc:
        raise BackupError(f"{path} cannot be read as a database: {exc}") from None
    if not has_sources:
        raise BackupError(f"{path} is not a ThreatCull database (it has no sources table)")
    if version > SCHEMA_VERSION:
        raise BackupError(
            f"{path} is from a newer ThreatCull (schema {version}; this version uses "
            f"schema {SCHEMA_VERSION}): restore it with that version or newer"
        )
    return version


def restore_backup(data_dir: Path, source: Path, *, now: datetime) -> RestoreReport:
    """Replace ``<data-dir>/threatcull.db`` with ``source``; ThreatCull must be stopped.

    Holds the data-directory lock throughout (``DataDirLocked`` if ``serve`` or ``run``
    holds it). Order: check ``source``, make a safety copy of the live database into
    ``backups/pre-restore-…db`` (skipped when there is none), then swap ``source`` in.
    The swap stages a checked copy first; a staging failure changes nothing. If the
    commit (sidecars removed, rename) fails, the safety copy goes back the same way
    and ``BackupError`` names what went wrong. The live database is never opened
    through ``connect()``, so nothing migrates it before the swap.
    """
    with data_dir_lock(data_dir):
        schema = check_backup(source)
        db_path = data_dir / DB_NAME
        if db_path.exists() and _same_file(source, db_path):
            raise BackupError(f"{source} is the live database: choose a backup file")
        safety: Path | None = None
        if db_path.exists():
            dest = default_backup_path(data_dir, prefix="pre-restore", now=now)
            ensure_backups_dir(data_dir)
            try:
                safety = create_backup(db_path, dest)
            except BackupError as exc:
                raise BackupError(
                    f"cannot make a safety copy of the current database ({exc}); nothing "
                    f"was changed. To restore anyway, move {db_path} and its -wal and -shm "
                    f"files out of {data_dir} first"
                ) from None
        try:
            staged = _stage(data_dir, source)
        except Exception as exc:
            # The live database and its -wal/-shm are untouched: no put-back.
            raise BackupError(f"restore failed: {_describe(exc)}; nothing was changed") from exc
        try:
            _commit(data_dir, staged)
        except Exception as exc:
            if safety is None:
                raise BackupError(f"restore failed: {_describe(exc)}") from exc
            try:
                _commit(data_dir, _stage(data_dir, safety))
            except Exception as put_back:
                raise BackupError(
                    f"restore failed: {_describe(exc)}; putting the safety copy back also "
                    f"failed: {_describe(put_back)}; copy {safety} to {db_path} by hand"
                ) from exc
            raise BackupError(
                f"restore failed: {_describe(exc)}; the previous database was put back "
                f"from the safety copy {safety}"
            ) from exc
        return RestoreReport(safety_copy=safety, schema=schema)


def _stage(data_dir: Path, source: Path) -> Path:
    """Copy ``source`` to a checked, fsynced temp file next to the database; return it.

    Touches nothing but the temp file, which it removes on failure.
    """
    tmp = data_dir / RESTORE_TMP_NAME
    try:
        tmp.unlink(missing_ok=True)  # a crashed restore's leftover; the lock makes it ours
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        with source.open("rb") as src, os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(src, out, _COPY_CHUNK)
            out.flush()
            os.fsync(out.fileno())
        check_backup(tmp)  # what lands is what was checked, even if the source changed
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _commit(data_dir: Path, staged: Path) -> None:
    """Drop the database's -wal/-shm and rename ``staged`` over it; the point of no return."""
    try:
        for name in SIDECARS:
            (data_dir / name).unlink(missing_ok=True)
        staged.replace(data_dir / DB_NAME)
        sync_directory(data_dir)
    finally:
        staged.unlink(missing_ok=True)


def _online_copy(db_path: Path, dest: Path) -> None:
    # mode=rw: never create a database that isn't there. Not connect(): no migration.
    uri = f"{db_path.resolve().as_uri()}?mode=rw"
    with (
        contextlib.closing(sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_S)) as src,
        contextlib.closing(sqlite3.connect(dest)) as out,
    ):
        src.backup(out)
        # The copy inherits WAL mode from the header; make it one self-contained file.
        out.execute("PRAGMA journal_mode = DELETE")


@contextlib.contextmanager
def _open_read_only(path: Path) -> Iterator[sqlite3.Connection]:
    # immutable=1: a WAL-mode file opened plain read-only still creates -wal/-shm beside it.
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
        yield conn


def _integrity_rows(conn: sqlite3.Connection) -> list[str]:
    return [str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()]


def _require_integrity(conn: sqlite3.Connection, path: Path) -> None:
    try:
        rows = _integrity_rows(conn)
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"integrity check of {path} failed: {exc}") from None
    if rows != ["ok"]:
        raise BackupError(f"integrity check of {path} failed: {'; '.join(rows[:3])}")


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.samefile(b)
    except OSError:
        return False


def _describe(exc: BaseException) -> str:
    if isinstance(exc, OSError) and exc.strerror:
        return f"{exc.strerror} ({exc.filename})" if exc.filename else exc.strerror
    return str(exc)
