# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "bench_matrix", ROOT / "scripts" / "bench_matrix.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_matrix"] = module
    spec.loader.exec_module(module)
    return module


bm = _load()

IMAGE = "img:test"


def _matrix(sizes: list[int], memories: list[str], cpus: list[str] | None = None) -> list[Any]:
    combos: list[Any] = bm.build_matrix(
        sizes,
        memories,
        cpus or ["1"],
        sources=4,
        overlap=0.3,
        duplicates=0.05,
        image=IMAGE,
    )
    return combos


class FakeRunner:
    def __init__(self, run_result: Any = None, timeout: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.run_result = run_result or bm.RunResult(0, json.dumps({"indicators": 5}), "")
        self.timeout = timeout

    def __call__(self, args: list[str], timeout: float | None) -> Any:
        self.calls.append(args)
        if args[:2] == ["docker", "run"]:
            if self.timeout:
                raise subprocess.TimeoutExpired(args, timeout or 0)
            return self.run_result
        return bm.RunResult(0)


def test_docker_args_exact() -> None:
    combo = _matrix([150000], ["512m"])[0]
    bench = Path("/x/scripts/bench.py")
    assert bm.docker_run_args(combo, "n1", "v1", bench) == [
        "docker", "run", "--rm", "--name", "n1",
        "--cpus", "1", "--memory", "512m", "--memory-swap", "512m",
        "--entrypoint", "python",
        "-v", "/x/scripts/bench.py:/bench.py:ro",
        "-v", "v1:/data",
        IMAGE, "/bench.py", "--json",
        "--lines", "150000", "--sources", "4", "--overlap", "0.3",
        "--duplicates", "0.05", "--kind", "domain",
    ]  # fmt: skip


def test_matrix_order_smallest_size_then_largest_memory() -> None:
    combos = _matrix([300000, 150000], ["512m", "4g", "1g", "2g"])
    order = [(c.lines, c.memory) for c in combos]
    assert order == [
        (150000, "4g"), (150000, "2g"), (150000, "1g"), (150000, "512m"),
        (300000, "4g"), (300000, "2g"), (300000, "1g"), (300000, "512m"),
    ]  # fmt: skip


def test_dry_run_prints_and_runs_nothing(tmp_path: Path) -> None:
    runner = FakeRunner()
    printed: list[str] = []
    out = tmp_path / "r.jsonl"
    bm.run_matrix(
        _matrix([100], ["1g", "2g"]),
        out,
        timeout_minutes=1,
        resume=False,
        dry_run=True,
        runner=runner,
        emit=printed.append,
    )
    assert runner.calls == []
    assert not out.exists()
    assert len(printed) == 2
    assert printed[0].startswith("docker run --rm --name ")
    assert "--memory 2g" in printed[0]


def test_resume_skips_finished(tmp_path: Path) -> None:
    out = tmp_path / "r.jsonl"
    combos = _matrix([100], ["2g", "1g", "512m"])
    done = {**combos[0].__dict__, "status": "ok"}
    failed = {**combos[1].__dict__, "status": "failed"}
    out.write_text(json.dumps(done) + "\n" + json.dumps(failed) + "\n")
    runner = FakeRunner()
    results = bm.run_matrix(
        combos,
        out,
        timeout_minutes=1,
        resume=True,
        dry_run=False,
        runner=runner,
        log=lambda _text: None,
    )
    assert [r["memory"] for r in results] == ["1g", "512m"]
    runs = [c for c in runner.calls if c[:2] == ["docker", "run"]]
    assert len([c for c in runs if "--json" in c]) == 2
    # The lists are generated once for the size, outside the memory limit, and reused.
    generated = [c for c in runs if "--generate-only" in c]
    assert len(generated) == 1
    assert "--memory" not in generated[0]
    volume = bm.lists_volume_name(combos[0])
    assert all(f"{volume}:/lists:ro" in c for c in runs if "--json" in c)
    assert runner.calls[-1] == ["docker", "volume", "rm", "-f", volume]
    assert len(out.read_text().splitlines()) == 4


def test_exit_137_is_oom_and_volume_removed() -> None:
    runner = FakeRunner(bm.RunResult(137, "", "killed"))
    record = bm.run_combo(_matrix([100], ["512m"])[0], 1, runner)
    assert record["status"] == "oom"
    assert record["report"] is None
    assert runner.calls[0][:3] == ["docker", "volume", "create"]
    assert runner.calls[-1][:4] == ["docker", "volume", "rm", "-f"]


def test_timeout_kills_container() -> None:
    runner = FakeRunner(timeout=True)
    record = bm.run_combo(_matrix([100], ["512m"])[0], 1, runner)
    assert record["status"] == "timeout"
    assert any(c[:2] == ["docker", "kill"] for c in runner.calls)
    assert runner.calls[-1][:4] == ["docker", "volume", "rm", "-f"]


def test_failure_keeps_stderr_tail() -> None:
    runner = FakeRunner(bm.RunResult(1, "", "x" * 600 + "boom"))
    record = bm.run_combo(_matrix([100], ["512m"])[0], 1, runner)
    assert record["status"] == "failed"
    assert len(record["error"]) == 500
    assert record["error"].endswith("boom")


def test_summary_rendering(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ok = {
        "lines": 1000000, "sources": 4, "overlap": 0.3, "duplicates": 0.05,
        "memory": "2g", "cpus": "1", "image": IMAGE, "status": "ok",
        "wall_seconds": 900.0, "error": None,
        "report": {
            "indicators": 3200000, "sightings": 4000000,
            "steps": {
                "first Fetch": {"seconds": 123.4},
                "unchanged Fetch": {"seconds": 5.0},
                "Compile": {"seconds": 60.0},
                "second Compile": {"seconds": 59.6},
            },
            "database_mb_after_compile": 1234.0, "output_mb": 80.0,
            "cgroup_memory_peak_mb": 1500.0,
        },
    }  # fmt: skip
    oom = {
        "lines": 3200000, "sources": 4, "overlap": 0.3, "duplicates": 0.05,
        "memory": "512m", "cpus": "1", "image": IMAGE, "status": "oom",
        "wall_seconds": 10.0, "report": None, "error": None,
    }  # fmt: skip
    path = tmp_path / "r.jsonl"
    path.write_text(json.dumps(oom) + "\n" + json.dumps(ok) + "\n")
    assert bm.main(["--summary", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("| Indicators | Sightings | Memory limit | CPUs |")
    assert lines[1].startswith("|---|")
    assert lines[3] == (
        "| 3,200,000 | 4,000,000 | 2g | 1 | 123 s | 5 s | 60 s | 60 s "
        "| 1,234 MB | 80 MB | 1,500 MB | ok |"
    )
    assert lines[2] == "| - | - | 512m | 1 | - | - | - | - | - | - | - | oom |"
