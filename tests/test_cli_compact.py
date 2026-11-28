# SPDX-License-Identifier: AGPL-3.0-only
"""`threatcull db compact`: give the space freed inside the database back to the disk."""

import contextlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from threatcull.cli import main
from threatcull.datadir import data_dir_lock


def _bloat(path: Path) -> None:
    """Fill the database with rows and delete them: the file keeps its size."""
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.executemany(
            "INSERT INTO indicators (value, kind) VALUES (?, 'domain')",
            ((f"host-{n:06}.example.test",) for n in range(60_000)),
        )
        conn.execute("DELETE FROM indicators")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def test_compact_shrinks_the_database_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    db = data / "threatcull.db"
    _bloat(db)
    before = db.stat().st_size
    capsys.readouterr()

    assert main(["--data-dir", str(data), "db", "compact"]) == 0

    assert db.stat().st_size < before / 2
    assert "Compacted the database" in capsys.readouterr().out
    # Still a working database.
    assert main(["--data-dir", str(data), "sources", "list"]) == 0


def test_compact_refuses_while_threatcull_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    capsys.readouterr()

    with data_dir_lock(data):  # what `serve` holds
        assert main(["--data-dir", str(data), "db", "compact"]) == 1

    assert "error:" in capsys.readouterr().err


def test_compact_needs_free_space_for_a_second_copy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    capsys.readouterr()
    usage = shutil.disk_usage(data)
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: usage._replace(free=1024))

    assert main(["--data-dir", str(data), "db", "compact"]) == 1

    assert "free" in capsys.readouterr().err
