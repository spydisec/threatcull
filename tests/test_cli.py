# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path

import pytest
import yaml

from threatcull.cli import main


def _catalog(tmp_path: Path) -> Path:
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "a.txt").write_text("45.9.20.1\n45.9.20.2\n", encoding="utf-8")
    (feeds / "b.txt").write_text("45.9.20.1\n", encoding="utf-8")
    (feeds / "c.txt").write_text("45.9.20.1\n", encoding="utf-8")
    (feeds / "nc.txt").write_text("45.9.20.9\n", encoding="utf-8")
    common = {
        "format": "plain",
        "kind": "ip",
        "category": "malicious",
        "licence_url": "https://example.com/l",
        "refresh_minutes": 60,
    }
    sources = [
        {
            **common,
            "id": f"src-{n}",
            "name": f"Source {n.upper()}",
            "url": (feeds / f"{n}.txt").as_uri(),
            "licence_class": "permissive",
            "business_use": "allowed",
            "licence": "MIT",
            "default_enabled": True,
        }
        for n in ("a", "b", "c")
    ]
    sources.append(
        {
            **common,
            "id": "src-nc",
            "name": "NC",
            "url": (feeds / "nc.txt").as_uri(),
            "licence_class": "noncommercial",
            "business_use": "forbidden",
            "licence": "CC BY-NC",
        }
    )
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({"sources": sources}), encoding="utf-8")
    return path


@pytest.fixture
def cli(tmp_path: Path) -> list[str]:
    return ["--data-dir", str(tmp_path / "data"), "--catalog", str(_catalog(tmp_path))]


def test_init_prints_feed_tokens_once(cli: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*cli, "init"]) == 0
    assert capsys.readouterr().out.count("Feed Token for Output") == 5
    assert main([*cli, "init"]) == 0
    assert "Feed Token" not in capsys.readouterr().out


def test_run_publishes_outputs_and_lookup_explains(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "run"]) == 0
    high = (tmp_path / "data" / "outputs" / "ip-high.txt").read_text()
    assert [line for line in high.splitlines() if not line.startswith("#")] == ["45.9.20.1"]
    capsys.readouterr()
    assert main([*cli, "lookup", "45.9.20.1"]) == 0
    out = capsys.readouterr().out
    assert "score 3 (high)" in out
    assert "Source A" in out
    assert "ip-high" in out
    assert "ip-medium (cap 25000)" in out


def test_a_noncommercial_source_can_be_enabled(
    cli: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "sources", "enable", "src-nc"]) == 0


def test_allowlist_commands(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "allow", "add", "45.9.20.1", "--note", "partner"]) == 0
    assert main([*cli, "allow", "list"]) == 0
    assert "45.9.20.1  partner" in capsys.readouterr().out
    assert main([*cli, "run"]) == 0
    medium = (tmp_path / "data" / "outputs" / "ip-medium.txt").read_text()
    assert "45.9.20.1" not in medium.replace("# ", "")
    assert main([*cli, "allow", "remove", "45.9.20.1"]) == 0
    assert main([*cli, "allow", "remove", "45.9.20.1"]) == 1


def test_sources_list_and_disable(cli: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*cli, "sources", "disable", "src-a"]) == 0
    capsys.readouterr()
    assert main([*cli, "sources", "list"]) == 0
    out = capsys.readouterr().out
    assert "off  src-a" in out
    assert "on   src-b" in out


def test_custom_source(cli: list[str], tmp_path: Path) -> None:
    hp = tmp_path / "hp.txt"
    hp.write_text("45.9.21.1\n", encoding="utf-8")
    assert (
        main(
            [
                *cli,
                "sources",
                "add-custom",
                "--id",
                "custom-hp",
                "--name",
                "Honeypot",
                "--url",
                hp.as_uri(),
                "--format",
                "plain",
                "--kind",
                "ip",
                "--category",
                "scanner",
                "--business-use",
                "allowed",
            ]
        )
        == 0
    )
    assert main([*cli, "sources", "enable", "custom-hp"]) == 0
    assert main([*cli, "fetch", "custom-hp"]) == 0


def test_fetch_reports_failures_on_stderr_and_exits_1(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "feeds" / "b.txt").unlink()
    assert main([*cli, "fetch"]) == 1
    captured = capsys.readouterr()
    assert "FAIL src-b: cannot read" in captured.err
    assert "FAIL" not in captured.out
    assert "ok   src-a" in captured.out
    assert "ok   src-c" in captured.out


def test_run_compiles_after_a_failed_fetch_then_exits_1(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "run"]) == 0
    (tmp_path / "feeds" / "b.txt").unlink()
    (tmp_path / "data" / "outputs" / "ip-high.txt").unlink()
    capsys.readouterr()
    assert main([*cli, "run"]) == 1
    captured = capsys.readouterr()
    assert "FAIL src-b" in captured.err
    assert "ip-high: 1" in captured.out
    assert (tmp_path / "data" / "outputs" / "ip-high.txt").exists()


def test_compile_blocked_exit_code(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "run"]) == 0
    (tmp_path / "feeds" / "a.txt").write_text("45.9.20.1\n", encoding="utf-8")
    (tmp_path / "feeds" / "b.txt").write_text("45.9.21.1\n", encoding="utf-8")
    (tmp_path / "feeds" / "c.txt").write_text("45.9.21.1\n", encoding="utf-8")
    assert main([*cli, "run"]) == 2
    assert "would shrink" in capsys.readouterr().out
    assert main([*cli, "compile", "--force"]) == 0


def test_outputs_list_and_rotate(cli: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*cli, "outputs", "list"]) == 0
    assert "ip-high" in capsys.readouterr().out
    assert main([*cli, "outputs", "rotate-token", "ip-high"]) == 0
    assert "Feed Token for Output 'ip-high'" in capsys.readouterr().out
    assert main([*cli, "outputs", "rotate-token", "nope"]) == 1


def test_lookup_rejects_private_values(cli: list[str]) -> None:
    assert main([*cli, "lookup", "10.0.0.1"]) == 1


def test_missing_catalog_file_reports_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["--data-dir", str(tmp_path / "data"), "--catalog", str(tmp_path / "missing.yaml")]
    assert main([*args, "init"]) == 1
    assert capsys.readouterr().err.startswith("error:")


def test_invalid_catalog_yaml_reports_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("sources: [unclosed", encoding="utf-8")
    args = ["--data-dir", str(tmp_path / "data"), "--catalog", str(bad)]
    assert main([*args, "init"]) == 1
    assert capsys.readouterr().err.startswith("error:")


def test_allow_import_file(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = tmp_path / "allow.csv"
    listing.write_text("value,note\n8.8.8.8,dns\nbad value\n", encoding="utf-8")
    assert main([*cli, "init"]) == 0
    capsys.readouterr()
    assert main([*cli, "allow", "import", str(listing)]) == 0
    out = capsys.readouterr().out
    assert "imported 1 new entry, 0 already present" in out
    assert "line 3: 'bad value'" in out
    assert main([*cli, "allow", "import", str(tmp_path / "missing.txt")]) == 1


def test_compile_reports_outputs_whose_guard_baseline_was_reset(
    cli: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "init"]) == 0
    assert main([*cli, "run"]) == 0
    assert main([*cli, "sources", "disable", "src-a"]) == 0
    capsys.readouterr()
    assert main([*cli, "compile"]) == 0
    assert "baseline reset (a Source that fed it was disabled)" in capsys.readouterr().out
