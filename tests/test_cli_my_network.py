# SPDX-License-Identifier: AGPL-3.0-only
"""`threatcull allow --mine` / `allow detect` and the your-network WARNING lines."""

from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

import threatcull.cli
from tests.test_cli import _catalog
from threatcull.cli import main
from threatcull.fetcher import FetchError, FetchResult
from threatcull.home_detect import Candidate, DetectPaths, detect_candidates
from threatcull.store.allowlist import AllowlistEntry

ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0114092D\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)


@pytest.fixture
def cli(tmp_path: Path) -> list[str]:
    return ["--data-dir", str(tmp_path / "data"), "--catalog", str(_catalog(tmp_path))]


@pytest.fixture
def fake_proc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "route").write_text(ROUTE, encoding="utf-8")
    (tmp_path / "resolv").write_text("nameserver 45.9.21.53\n", encoding="utf-8")
    paths = DetectPaths(
        route=tmp_path / "route",
        resolv=tmp_path / "resolv",
        fib_trie=tmp_path / "none",
        if_inet6=tmp_path / "none",
    )

    def detect(
        *, existing: Sequence[AllowlistEntry] = (), extra_hosts: Iterable[str] = ()
    ) -> list[Candidate]:
        return detect_candidates(existing=existing, extra_hosts=extra_hosts, paths=paths)

    monkeypatch.setattr(threatcull.cli, "detect_candidates", detect)


class _PublicFetcher:
    calls = 0

    def __call__(self, url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        _PublicFetcher.calls += 1
        return FetchResult("ok", "45.9.20.99\n")


@pytest.fixture
def public_fetcher(monkeypatch: pytest.MonkeyPatch) -> type[_PublicFetcher]:
    _PublicFetcher.calls = 0
    monkeypatch.setattr(threatcull.cli, "public_ip_fetcher", _PublicFetcher)
    return _PublicFetcher


def test_allow_add_mine_list_remove(cli: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*cli, "allow", "add", "45.9.20.1", "--note", "office", "--mine"]) == 0
    assert main([*cli, "allow", "list"]) == 0
    assert "45.9.20.1  mine  office" in capsys.readouterr().out
    assert main([*cli, "allow", "remove", "45.9.20.1"]) == 0
    capsys.readouterr()
    assert main([*cli, "allow", "list"]) == 0
    assert "45.9.20.1" not in capsys.readouterr().out


def test_allow_add_private_explains(cli: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*cli, "allow", "add", "192.168.1.10", "--mine"]) == 1
    assert "no allowlist entry is needed" in capsys.readouterr().err


def test_run_warns_when_a_source_lists_your_network(
    cli: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli, "allow", "add", "45.9.20.1", "--mine"]) == 0
    capsys.readouterr()
    assert main([*cli, "run"]) == 0
    captured = capsys.readouterr()
    assert "WARNING: your network is listed by src-a,src-b,src-c: 45.9.20.1" in captured.err
    assert "45.9.20.1" not in captured.out
    assert main([*cli, "compile"]) == 0
    assert "WARNING: your network is listed by" in capsys.readouterr().err


def test_detect_prints_candidates_without_adding_or_calling_out(
    cli: list[str],
    fake_proc: None,
    public_fetcher: type[_PublicFetcher],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([*cli, "allow", "detect"]) == 0
    out = capsys.readouterr().out
    assert "45.9.20.1  default gateway (eth0)" in out
    assert "45.9.21.53  DNS resolver in /etc/resolv.conf" in out
    assert public_fetcher.calls == 0
    assert main([*cli, "allow", "list"]) == 0
    assert "45.9.20.1" not in capsys.readouterr().out


def test_detect_apply_adds_as_mine(
    cli: list[str],
    fake_proc: None,
    public_fetcher: type[_PublicFetcher],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([*cli, "allow", "detect", "--apply"]) == 0
    capsys.readouterr()
    assert main([*cli, "allow", "list"]) == 0
    out = capsys.readouterr().out
    assert "45.9.20.1  mine  default gateway (eth0)" in out
    assert public_fetcher.calls == 0
    assert main([*cli, "allow", "detect"]) == 0
    assert "no new candidates" in capsys.readouterr().out


def test_detect_public_ip_only_when_asked(
    cli: list[str],
    fake_proc: None,
    public_fetcher: type[_PublicFetcher],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([*cli, "allow", "detect", "--public-ip"]) == 0
    assert public_fetcher.calls == 1
    assert "45.9.20.99  public IP reported by api.ipify.org" in capsys.readouterr().out


def test_detect_public_ip_failure_is_reported(
    cli: list[str],
    fake_proc: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def offline(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        raise FetchError("offline")

    monkeypatch.setattr(threatcull.cli, "public_ip_fetcher", lambda: offline)
    assert main([*cli, "allow", "detect", "--public-ip"]) == 0
    captured = capsys.readouterr()
    assert "could not learn the public IP" in captured.err
    assert "45.9.20.1  default gateway (eth0)" in captured.out


def test_allow_import_as_mine(
    cli: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = tmp_path / "mine.txt"
    listing.write_text("45.9.20.1\n192.168.1.10\n", encoding="utf-8")
    assert main([*cli, "init"]) == 0
    capsys.readouterr()
    assert main([*cli, "allow", "import", str(listing), "--mine"]) == 0
    out = capsys.readouterr().out
    assert "imported 1 new entry, 0 already present" in out
    assert "line 2: '192.168.1.10'" in out
