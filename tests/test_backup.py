# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import errno
import multiprocessing
import os
import shutil
import sqlite3
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from threatcull import backup
from threatcull.backup import (
    BackupError,
    check_backup,
    create_backup,
    default_backup_path,
    restore_backup,
)
from threatcull.datadir import DB_LOCK_NAME, LOCK_NAME, DataDirLocked, data_dir_lock
from threatcull.store import db as store_db
from threatcull.store.db import SCHEMA_VERSION, connect

NOW = datetime(2026, 11, 2, 9, 30, 5, tzinfo=UTC)
DB = "threatcull.db"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _live_db(data_dir: Path, marker: str = "live") -> Path:
    """A migrated ThreatCull database holding one recognisable setting."""
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / DB
    with contextlib.closing(connect(path)) as conn:
        conn.execute("INSERT INTO settings (key, value) VALUES ('marker', ?)", (marker,))
    return path


def _marker(path: Path) -> str:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'marker'").fetchone()
    return str(row[0])


def _backup_of(tmp_path: Path, marker: str) -> Path:
    """A finished backup file whose marker setting is ``marker``."""
    source_dir = tmp_path / f"src-{marker}"
    db_path = _live_db(source_dir, marker)
    return create_backup(db_path, tmp_path / f"{marker}.db")


# --- create --------------------------------------------------------------------------


def test_default_backup_path_uses_utc_stamp(tmp_path: Path) -> None:
    assert default_backup_path(tmp_path, now=NOW) == (
        tmp_path / "backups" / "threatcull-20261102T093005Z.db"
    )
    assert default_backup_path(tmp_path, prefix="pre-restore", now=NOW).name == (
        "pre-restore-20261102T093005Z.db"
    )


def test_backup_while_writing_is_consistent(tmp_path: Path) -> None:
    db_path = _live_db(tmp_path / "data")
    with contextlib.closing(connect(db_path)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS t_rows (n INTEGER)")
        conn.executemany("INSERT INTO t_rows VALUES (?)", [(i,) for i in range(2000)])
    stop = threading.Event()
    counts: list[int] = []

    def writer() -> None:
        with contextlib.closing(connect(db_path)) as w:
            n = 2000
            while not stop.is_set():
                w.execute("INSERT INTO t_rows VALUES (?)", (n,))  # autocommit: one row per commit
                n += 1
                counts.append(n)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        while len(counts) < 50:
            pass
        start = counts[-1]
        copy = create_backup(db_path, tmp_path / "copy.db")
    finally:
        stop.set()
        thread.join(30)
    assert check_backup(copy) == SCHEMA_VERSION
    with contextlib.closing(sqlite3.connect(copy)) as c:
        rows = c.execute("SELECT count(*), max(n) FROM t_rows").fetchone()
    assert start <= rows[0] <= counts[-1]
    assert rows[1] == rows[0] - 1  # a prefix of the inserts, nothing torn


def test_backup_file_mode_is_0600_and_refuses_overwrite(tmp_path: Path) -> None:
    db_path = _live_db(tmp_path / "data")
    dest = tmp_path / "out.db"
    assert create_backup(db_path, dest) == dest
    assert _mode(dest) == 0o600
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / "out.db-wal").exists()
    before = dest.read_bytes()
    with pytest.raises(BackupError, match="already exists"):
        create_backup(db_path, dest)
    assert dest.read_bytes() == before


def test_backup_refuses_missing_folder_and_missing_database(tmp_path: Path) -> None:
    db_path = _live_db(tmp_path / "data")
    with pytest.raises(BackupError, match="does not exist"):
        create_backup(db_path, tmp_path / "nope" / "out.db")
    assert not (tmp_path / "nope").exists()
    with pytest.raises(BackupError, match="no database"):
        create_backup(tmp_path / "empty" / DB, tmp_path / "out.db")
    assert not (tmp_path / "empty" / DB).exists()
    assert not (tmp_path / "out.db").exists()


def test_failed_integrity_check_leaves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _live_db(tmp_path / "data")
    monkeypatch.setattr(backup, "_integrity_rows", lambda conn: ["*** page 3 is never used"])
    with pytest.raises(BackupError, match="integrity"):
        create_backup(db_path, tmp_path / "out.db")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["data"]


def test_backup_is_a_single_file(tmp_path: Path) -> None:
    """The copy needs no -wal: restoring copies one file."""
    db_path = _live_db(tmp_path / "data")
    copy = create_backup(db_path, tmp_path / "out.db")
    with contextlib.closing(sqlite3.connect(copy)) as c:
        assert c.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


# --- check ---------------------------------------------------------------------------


def test_check_refuses_not_sqlite_truncated_foreign_and_newer_schema(tmp_path: Path) -> None:
    good = _backup_of(tmp_path, "good")
    assert check_backup(good) == SCHEMA_VERSION

    junk = tmp_path / "junk.db"
    junk.write_text("not a database\n" * 100)
    with pytest.raises(BackupError, match="not a SQLite database"):
        check_backup(junk)

    truncated = tmp_path / "truncated.db"
    data = good.read_bytes()
    truncated.write_bytes(data[: len(data) // 2])
    with pytest.raises(BackupError):
        check_backup(truncated)

    foreign = tmp_path / "foreign.db"
    with contextlib.closing(sqlite3.connect(foreign)) as c:
        c.execute("CREATE TABLE notes (x)")
        c.commit()
    with pytest.raises(BackupError, match="not a ThreatCull database"):
        check_backup(foreign)

    newer = tmp_path / "newer.db"
    newer.write_bytes(data)
    with contextlib.closing(sqlite3.connect(newer)) as c:
        c.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 3}")
    with pytest.raises(BackupError, match=rf"schema {SCHEMA_VERSION + 3}.*schema {SCHEMA_VERSION}"):
        check_backup(newer)

    with pytest.raises(BackupError, match="not a file"):
        check_backup(tmp_path / "missing.db")


def test_check_writes_nothing_next_to_the_file(tmp_path: Path) -> None:
    folder = tmp_path / "given"
    folder.mkdir()
    wal_db = folder / "wal.db"
    with contextlib.closing(sqlite3.connect(wal_db)) as c:
        c.execute("PRAGMA journal_mode = WAL")
        store_db.migrate(c)
    assert sorted(p.name for p in folder.iterdir()) == ["wal.db"]
    assert check_backup(wal_db) == SCHEMA_VERSION
    assert sorted(p.name for p in folder.iterdir()) == ["wal.db"]


def test_check_refuses_a_file_with_a_wal_beside_it(tmp_path: Path) -> None:
    good = _backup_of(tmp_path, "good")
    (tmp_path / "good.db-wal").write_bytes(b"x" * 100)
    with pytest.raises(BackupError, match="-wal"):
        check_backup(good)


def test_integrity_failure_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = _backup_of(tmp_path, "good")
    monkeypatch.setattr(backup, "_integrity_rows", lambda conn: ["ok", "extra"])
    with pytest.raises(BackupError, match="integrity"):
        check_backup(good)


# --- restore -------------------------------------------------------------------------


def test_restore_replaces_data_and_removes_sidecars(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    (data_dir / "threatcull.db-wal").write_bytes(b"stale wal")
    (data_dir / "threatcull.db-shm").write_bytes(b"stale shm")
    source = _backup_of(tmp_path, "new")
    source_bytes = source.read_bytes()

    report = restore_backup(data_dir, source, now=NOW)

    assert report.schema == SCHEMA_VERSION
    assert report.safety_copy == data_dir / "backups" / "pre-restore-20261102T093005Z.db"
    assert _marker(report.safety_copy) == "old"
    assert _mode(report.safety_copy) == 0o600
    assert _mode(data_dir / "backups") == 0o700
    assert not (data_dir / "threatcull.db-wal").exists()
    assert not (data_dir / "threatcull.db-shm").exists()
    assert (data_dir / DB).read_bytes() == source_bytes
    assert _marker(data_dir / DB) == "new"
    assert not (data_dir / ".threatcull.db.restore.tmp").exists()
    assert source.read_bytes() == source_bytes  # the operator's file is untouched


def test_restore_refuses_bad_file_before_touching_anything(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    junk = tmp_path / "junk.db"
    junk.write_text("nope" * 100)
    before = sorted(p.name for p in data_dir.iterdir())
    with pytest.raises(BackupError):
        restore_backup(data_dir, junk, now=NOW)
    assert sorted(p.name for p in data_dir.iterdir()) == sorted({*before, LOCK_NAME, DB_LOCK_NAME})
    assert _marker(data_dir / DB) == "old"


def _hold_lock(path: str, ready: Any, release: Any) -> None:
    with data_dir_lock(Path(path)):
        ready.set()
        release.wait(30)


def test_restore_refuses_while_locked(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    source = _backup_of(tmp_path, "new")
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold_lock, args=(str(data_dir), ready, release))
    child.start()
    try:
        assert ready.wait(30)
        with pytest.raises(DataDirLocked, match="stop it first"):
            restore_backup(data_dir, source, now=NOW)
    finally:
        release.set()
        child.join(30)
    assert _marker(data_dir / DB) == "old"
    assert not (data_dir / "backups").exists()


def test_leftover_lock_file_does_not_block_restore(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    (data_dir / LOCK_NAME).write_text("")
    restore_backup(data_dir, _backup_of(tmp_path, "new"), now=NOW)
    assert _marker(data_dir / DB) == "new"


def test_restore_on_empty_data_dir_skips_safety_copy(tmp_path: Path) -> None:
    data_dir = tmp_path / "fresh"
    data_dir.mkdir()
    report = restore_backup(data_dir, _backup_of(tmp_path, "new"), now=NOW)
    assert report.safety_copy is None
    assert not (data_dir / "backups").exists()
    assert _marker(data_dir / DB) == "new"


def test_failure_mid_swap_puts_the_original_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    source = _backup_of(tmp_path, "new")
    real_replace = os.replace
    calls: list[str] = []

    def flaky_replace(src: Any, dst: Any) -> None:
        calls.append(str(dst))
        if len(calls) == 1:
            raise OSError(28, "No space left on device")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    with pytest.raises(BackupError) as caught:
        restore_backup(data_dir, source, now=NOW)
    message = str(caught.value)
    assert "No space left on device" in message
    assert "pre-restore-20261102T093005Z.db" in message
    assert len(calls) == 2
    assert _marker(data_dir / DB) == "old"
    assert (data_dir / "backups" / "pre-restore-20261102T093005Z.db").exists()
    assert not (data_dir / ".threatcull.db.restore.tmp").exists()


def test_staging_failure_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    # No fake -wal/-shm here: the safety copy's own SQLite connection would fold and
    # delete them, which is SQLite's doing, not the staging step's.
    before = {p.name: p.read_bytes() for p in data_dir.iterdir() if p.is_file()}
    source = _backup_of(tmp_path, "new")
    copies: list[Any] = []

    def full_disk(src: Any, dst: Any, length: int = 0) -> None:
        copies.append(src)
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(shutil, "copyfileobj", full_disk)
    with pytest.raises(BackupError) as caught:
        restore_backup(data_dir, source, now=NOW)
    message = str(caught.value)
    assert "No space left on device" in message
    assert "nothing was changed" in message
    assert "by hand" not in message
    assert len(copies) == 1  # no put-back attempted
    after = {p.name: p.read_bytes() for p in data_dir.iterdir() if p.is_file()}
    assert after == {**before, LOCK_NAME: b"", DB_LOCK_NAME: b""}
    assert not (data_dir / ".threatcull.db.restore.tmp").exists()


def test_failed_put_back_names_both_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")
    source = _backup_of(tmp_path, "new")
    errors = iter(["first failure", "second failure"])

    def broken_replace(src: Any, dst: Any) -> None:
        raise OSError(5, next(errors))

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(BackupError) as caught:
        restore_backup(data_dir, source, now=NOW)
    message = str(caught.value)
    assert "first failure" in message
    assert "second failure" in message
    assert "pre-restore-20261102T093005Z.db" in message
    assert not (data_dir / ".threatcull.db.restore.tmp").exists()


def test_restore_refuses_when_safety_copy_fails(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / DB).write_text("corrupt" * 100)
    with pytest.raises(BackupError, match="safety copy"):
        restore_backup(data_dir, _backup_of(tmp_path, "new"), now=NOW)
    assert (data_dir / DB).read_text() == "corrupt" * 100
    assert not list((data_dir / "backups").iterdir())


def test_restore_refuses_the_live_database_itself(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    live = _live_db(data_dir, "old")
    with pytest.raises(BackupError, match="live database"):
        restore_backup(data_dir, live, now=NOW)
    assert _marker(live) == "old"


def test_older_schema_restores_and_migrates_on_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = tmp_path / "old-schema.db"
    with contextlib.closing(sqlite3.connect(old, isolation_level=None)) as c:
        monkeypatch.setattr(store_db, "_MIGRATIONS", store_db._MIGRATIONS[:1])
        store_db.migrate(c)
        monkeypatch.undo()
        assert c.execute("PRAGMA user_version").fetchone()[0] == 1
    data_dir = tmp_path / "data"
    _live_db(data_dir, "old")

    report = restore_backup(data_dir, old, now=NOW)

    assert report.schema == 1
    with contextlib.closing(connect(data_dir / DB)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
