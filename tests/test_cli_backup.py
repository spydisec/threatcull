# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from threatcull import backup, cli
from threatcull.cli import main
from threatcull.store.db import SCHEMA_VERSION

FEEDS_EMPTY = (
    "Feeds stay empty until the next Compile: click Run now or wait for the schedule. "
    "The Output files on disk are from before the restore until then."
)


def _marker(path: Path) -> str | None:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'marker'").fetchone()
    return None if row is None else str(row[0])


def _set_marker(path: Path, value: str) -> None:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('marker', ?)", (value,))
        conn.commit()


def test_create_then_restore_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    _set_marker(data / "threatcull.db", "before")
    capsys.readouterr()

    assert main(["--data-dir", str(data), "backup", "create"]) == 0
    out = capsys.readouterr().out.strip()
    made = Path(out)
    assert made.parent == data / "backups"
    assert made.name.startswith("threatcull-")
    assert made.name.endswith("Z.db")
    assert stat.S_IMODE(made.stat().st_mode) == 0o600
    assert stat.S_IMODE((data / "backups").stat().st_mode) == 0o700

    _set_marker(data / "threatcull.db", "after")
    assert main(["--data-dir", str(data), "backup", "restore", str(made)]) == 0
    out = capsys.readouterr().out
    assert _marker(data / "threatcull.db") == "before"
    safety = next((data / "backups").glob("pre-restore-*.db"))
    assert str(safety) in out
    assert f"schema {SCHEMA_VERSION}" in out
    assert FEEDS_EMPTY in out
    assert _marker(safety) == "after"


def test_create_with_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    target = tmp_path / "elsewhere.db"
    assert main(["--data-dir", str(data), "backup", "create", "--output", str(target)]) == 0
    assert capsys.readouterr().out.strip().endswith(str(target))
    assert not (data / "backups").exists()

    assert main(["--data-dir", str(data), "backup", "create", "--output", str(target)]) == 1
    assert "already exists" in capsys.readouterr().err

    missing = tmp_path / "no-such-folder" / "x.db"
    assert main(["--data-dir", str(data), "backup", "create", "--output", str(missing)]) == 1
    assert "error:" in capsys.readouterr().err
    assert not missing.parent.exists()


def test_create_without_database_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "backup", "create"]) == 1
    assert "no database" in capsys.readouterr().err
    assert not (data / "threatcull.db").exists()


def test_create_refuses_same_second_default_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    monkeypatch.setattr(cli, "utcnow", lambda: datetime(2026, 11, 2, 1, 2, 3, tzinfo=UTC))
    assert main(["--data-dir", str(data), "backup", "create"]) == 0
    capsys.readouterr()
    assert main(["--data-dir", str(data), "backup", "create"]) == 1
    assert "--output" in capsys.readouterr().err


def test_backup_commands_never_open_the_live_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "init"]) == 0
    _set_marker(data / "threatcull.db", "before")
    events: list[str] = []
    real_restore = backup.restore_backup

    def no_connect(*args: Any, **kwargs: Any) -> Any:
        events.append("connect")
        raise AssertionError("backup commands must not call connect()")

    def recording_restore(*args: Any, **kwargs: Any) -> Any:
        events.append("restore")
        return real_restore(*args, **kwargs)

    monkeypatch.setattr(cli, "connect", no_connect)
    monkeypatch.setattr(cli, "restore_backup", recording_restore)
    assert main(["--data-dir", str(data), "backup", "create", "-o", str(tmp_path / "b.db")]) == 0
    assert main(["--data-dir", str(data), "backup", "restore", str(tmp_path / "b.db")]) == 0
    assert events == ["restore"]


def test_restore_errors_are_one_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    junk = tmp_path / "junk.db"
    junk.write_text("junk" * 100)
    assert main(["--data-dir", str(data), "backup", "restore", str(junk)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert err.count("\n") == 1
