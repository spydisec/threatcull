# SPDX-License-Identifier: AGPL-3.0-only
"""Database and Output sizes for the dashboard, Settings and /api/v1/status (#61)."""

from pathlib import Path

import pytest

from threatcull.datadir import storage_bytes
from threatcull.web.templating import _size


def test_storage_counts_the_database_with_its_wal_files_and_the_outputs(tmp_path: Path) -> None:
    (tmp_path / "threatcull.db").write_bytes(b"x" * 1000)
    (tmp_path / "threatcull.db-wal").write_bytes(b"x" * 200)
    (tmp_path / "secret.key").write_bytes(b"x" * 64)  # not part of the database
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    (outputs / "ip-high.txt").write_bytes(b"x" * 300)
    (outputs / "domains-malicious.txt").write_bytes(b"x" * 50)
    assert storage_bytes(tmp_path) == (1200, 350)


def test_storage_of_an_empty_data_dir_is_zero(tmp_path: Path) -> None:
    assert storage_bytes(tmp_path) == (0, 0)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (None, ""),
        (0, "0 B"),
        (950, "950 B"),
        (2048, "2.0 KB"),
        (100_352_000, "95.7 MB"),
        (1_610_612_736, "1.5 GB"),
        (3 * 1024**4, "3.0 TB"),
    ],
)
def test_size_filter(value: int | None, text: str) -> None:
    assert _size(value) == text
