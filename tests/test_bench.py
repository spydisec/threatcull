# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    # The measured steps run in spawned child processes, which import ``bench`` by name.
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module("bench")


bench = _load()

STEPS = ["first Fetch", "unchanged Fetch", "Compile", "second Compile"]


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, Any]:
    assert bench.main([*argv, "--json"]) == 0
    report: dict[str, Any] = json.loads(capsys.readouterr().out)
    return report


def test_several_overlapping_sources(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = _run(capsys, "--lines", "300", "--sources", "3", "--overlap", "0.5")
    assert list(report["steps"]) == STEPS
    assert all(step["ok"] for step in report["steps"].values())
    assert report["list"]["sources"] == 3
    assert report["list"]["overlap"] == 0.5
    # Regenerate the lists the script wrote: the Sightings are their distinct entries.
    first = bench.write_list(tmp_path / "l1.txt", 300, 0.4, "domain", "plain", index=0)
    distinct = [first]
    for index in (1, 2):
        distinct.append(
            bench.write_list(
                tmp_path / f"l{index + 1}.txt",
                300,
                0.4,
                "domain",
                "plain",
                index=index,
                pool=first,
                overlap=0.5,
            )
        )
    assert report["sightings"] == sum(len(entries) for entries in distinct)
    assert report["indicators"] == report["list"]["unique"]
    assert report["indicators"] < report["sightings"]
    for name in ("Compile", "second Compile"):
        assert report["steps"][name]["stages"]
    assert "stages" not in report["steps"]["first Fetch"]
    assert report["steps"]["first Fetch"]["lines_per_second"] > 0
    assert {"memory_limit_mb", "cpu_limit"} <= set(report["environment"])
    assert "cgroup_memory_peak_mb" in report


def test_default_run_keeps_its_keys(capsys: pytest.CaptureFixture[str]) -> None:
    report = _run(capsys, "--lines", "200")
    assert list(report["steps"])[:3] == STEPS[:3]
    assert {"environment", "list", "steps", "database_mb_after_fetch"} <= set(report)
    assert {"database_mb_after_compile", "output_mb"} <= set(report)
    assert {"lines", "duplicates", "kind", "format", "unique", "size_mb"} <= set(report["list"])
    assert {"platform", "cpus", "python", "sqlite"} <= set(report["environment"])
    assert {"ok", "seconds", "peak_rss_mb", "detail"} <= set(report["steps"]["Compile"])
    assert report["list"]["sources"] == 1
    assert report["indicators"] == report["sightings"] == report["list"]["unique"]


def test_source_ids() -> None:
    assert bench.source_id(1, 1) == "custom-bench"
    assert bench.source_id(2, 3) == "custom-bench-2"


def test_table_prints(capsys: pytest.CaptureFixture[str]) -> None:
    assert bench.main(["--lines", "200", "--sources", "2", "--overlap", "0.5"]) == 0
    out = capsys.readouterr().out
    assert "second Compile" in out
    assert "Indicators:" in out


@pytest.mark.parametrize("argv", [["--sources", "0"], ["--sources", "51"], ["--overlap", "1"]])
def test_bad_flags(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        bench.parse_args(argv)


def test_cgroup_readers(tmp_path: Path) -> None:
    assert bench.memory_limit_mb(tmp_path) is None
    assert bench.cpu_limit(tmp_path) is None
    assert bench.cgroup_memory_peak_mb(tmp_path) is None
    (tmp_path / "memory.max").write_text("max\n")
    assert bench.memory_limit_mb(tmp_path) is None
    (tmp_path / "memory.max").write_text(str(512 * 1024 * 1024))
    assert bench.memory_limit_mb(tmp_path) == 512
    (tmp_path / "cpu.max").write_text("150000 100000\n")
    assert bench.cpu_limit(tmp_path) == 1.5
    (tmp_path / "cpu.max").write_text("max 100000\n")
    assert bench.cpu_limit(tmp_path) is None
    (tmp_path / "memory.peak").write_text(str(2 * 1024 * 1024))
    assert bench.cgroup_memory_peak_mb(tmp_path) == 2


def test_cgroup_v1_limit(tmp_path: Path) -> None:
    (tmp_path / "memory").mkdir()
    limit = tmp_path / "memory" / "memory.limit_in_bytes"
    limit.write_text(str(256 * 1024 * 1024))
    assert bench.memory_limit_mb(tmp_path) == 256
    limit.write_text("9223372036854771712")
    assert bench.memory_limit_mb(tmp_path) is None


def test_lists_are_generated_once_and_reused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lists = tmp_path / "lists"
    flags = ["--lines", "200", "--sources", "2", "--overlap", "0.5", "--lists-dir", str(lists)]

    assert bench.main([*flags, "--generate-only"]) == 0
    capsys.readouterr()
    written = {path.name: path.stat().st_mtime_ns for path in lists.iterdir()}
    assert bench.main([*flags, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert sorted(written) == ["list-1.txt", "list-2.txt", "lists.json"]
    assert {path.name: path.stat().st_mtime_ns for path in lists.iterdir()} == written
    assert report["list"]["unique"] == json.loads((lists / "lists.json").read_text())["unique"]
    assert all(step["ok"] for step in report["steps"].values())


def test_generate_only_needs_a_lists_dir() -> None:
    with pytest.raises(SystemExit):
        bench.main(["--generate-only"])
