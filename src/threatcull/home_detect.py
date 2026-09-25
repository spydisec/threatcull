# SPDX-License-Identifier: AGPL-3.0-only
"""Suggest Home Network entries from this host's own configuration.

Detection only reads local files (``/proc`` and ``/etc/resolv.conf``); it never
sends a packet, not even a DNS query. The one exception is
:func:`detect_public_ip`, which asks ``api.ipify.org`` and runs only when the
operator explicitly requests it. Air-gapped installs never call it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from threatcull.fetcher import USER_AGENT, Fetcher, FetchError, FetchResult, HttpFetcher
from threatcull.indicators import normalize
from threatcull.policy.allowlist import Allowlist
from threatcull.store.allowlist import AllowlistEntry, normalize_allow_value

IPIFY_URL = "https://api.ipify.org"
PUBLIC_IP_REASON = "public IP reported by api.ipify.org"
PUBLIC_IP_TIMEOUT = 5.0
_PUBLIC_IP_MAX_BYTES = 1024
_RTF_GATEWAY = 0x2
_IPV6_HEX_LENGTH = 32
_ROUTE_FIELDS = 4  # Iface, Destination, Gateway, Flags
_NAMESERVER_FIELDS = 2


@dataclass(frozen=True, slots=True)
class Candidate:
    value: str
    reason: str


@dataclass(frozen=True, slots=True)
class DetectPaths:
    route: Path = Path("/proc/net/route")
    resolv: Path = Path("/etc/resolv.conf")
    fib_trie: Path = Path("/proc/net/fib_trie")
    if_inet6: Path = Path("/proc/net/if_inet6")


class HomeDetector(Protocol):
    """The shape of :func:`detect_candidates` as the web app calls it."""

    def __call__(
        self, *, existing: Sequence[AllowlistEntry] = (), extra_hosts: Iterable[str] = ()
    ) -> list[Candidate]: ...


def _lines(path: Path) -> list[str]:
    """The file's lines, or none at all when it is missing (e.g. not Linux)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def default_gateways(route: Path) -> list[tuple[str, str]]:
    """``(gateway, interface)`` of each IPv4 default route in ``/proc/net/route``.

    The kernel prints addresses as host-order hex, so on the little-endian
    machines Linux runs on ``0114092D`` is ``45.9.20.1``.
    """
    found: list[tuple[str, str]] = []
    for line in _lines(route)[1:]:
        fields = line.split()
        if len(fields) < _ROUTE_FIELDS:
            continue
        iface, destination, gateway, flags = fields[:4]
        try:
            if int(destination, 16) != 0 or not int(flags, 16) & _RTF_GATEWAY:
                continue
            address = ipaddress.IPv4Address(bytes.fromhex(gateway)[::-1])
        except ValueError:
            continue
        found.append((str(address), iface))
    return found


def resolvers(resolv: Path) -> list[str]:
    """``nameserver`` addresses in ``resolv.conf`` (zone ids such as ``%eth0`` dropped)."""
    found: list[str] = []
    for line in _lines(resolv):
        fields = line.split()
        if len(fields) >= _NAMESERVER_FIELDS and fields[0] == "nameserver":
            found.append(fields[1].split("%", 1)[0])
    return found


def local_addresses(paths: DetectPaths) -> list[str]:
    """This host's own addresses: IPv4 from ``fib_trie``, IPv6 from ``if_inet6``."""
    found: list[str] = []
    last = ""
    for line in _lines(paths.fib_trie):
        text = line.strip()
        if text.startswith("|--"):
            last = text[3:].strip()
        elif text.startswith("/32 host LOCAL") and last and last not in found:
            found.append(last)
    for line in _lines(paths.if_inet6):
        fields = line.split()
        if not fields or len(fields[0]) != _IPV6_HEX_LENGTH:
            continue
        try:
            found.append(str(ipaddress.IPv6Address(int(fields[0], 16))))
        except ValueError:
            continue
    return found


def detect_candidates(
    *,
    existing: Sequence[AllowlistEntry] = (),
    extra_hosts: Iterable[str] = (),
    paths: DetectPaths | None = None,
    host_addresses: Callable[[], Iterable[str]] | None = None,
) -> list[Candidate]:
    """Public addresses of this host, its default gateway and DNS resolvers.

    ``extra_hosts`` are names or addresses this server is reached at (the web UI
    passes the request's own host). Anything private or special-purpose (which
    ``normalize_allow_value`` rejects) and anything ``existing`` already covers is
    left out. Reads local files only; missing files are skipped silently.
    """
    paths = paths or DetectPaths()
    hosts = host_addresses() if host_addresses is not None else local_addresses(paths)
    raw: list[tuple[str, str]] = [(value, "address of this host") for value in hosts]
    raw += [(value, "address this server is reached at") for value in extra_hosts]
    raw += [(gw, f"default gateway ({iface})") for gw, iface in default_gateways(paths.route)]
    raw += [(value, "DNS resolver in /etc/resolv.conf") for value in resolvers(paths.resolv)]
    covered = Allowlist(existing)
    seen: set[str] = set()
    candidates: list[Candidate] = []
    for value, reason in raw:
        try:
            indicator = normalize_allow_value(value)
        except ValueError:
            continue
        if indicator.value in seen or covered.match(indicator.value, indicator.kind):
            continue
        seen.add(indicator.value)
        candidates.append(Candidate(indicator.value, reason))
    return candidates


def _public_ip_client() -> httpx.Client:
    """The httpx.Client :func:`public_ip_fetcher` uses: short timeout, no redirects followed."""
    return httpx.Client(timeout=PUBLIC_IP_TIMEOUT, headers={"User-Agent": USER_AGENT})


def public_ip_fetcher() -> Fetcher:
    """A Fetcher for :func:`detect_public_ip`: short timeout, no retries, tiny body cap.

    Built fresh for the single call :func:`detect_public_ip` makes; that call closes
    the underlying httpx.Client afterwards, so nothing is left open.
    """
    client = _public_ip_client()
    fetch = HttpFetcher(client, max_bytes=_PUBLIC_IP_MAX_BYTES, retry_delays=())

    def fetcher(url: str, *, etag: str | None, last_modified: str | None) -> FetchResult:
        try:
            return fetch(url, etag=etag, last_modified=last_modified)
        finally:
            client.close()

    return fetcher


def detect_public_ip(fetcher: Fetcher) -> str | None:
    """This network's public IP as ``api.ipify.org`` sees it; ``None`` if unknown.

    Contacts the internet: call it only when the operator asks. The reply must
    be exactly one public address, or it is ignored.
    """
    try:
        result = fetcher(IPIFY_URL, etag=None, last_modified=None)
    except FetchError:
        return None
    text = result.text.strip()
    if not text or len(text.split()) != 1 or "/" in text:
        return None
    indicator = normalize(text, "ip")
    return indicator.value if indicator is not None and indicator.kind == "ip" else None


def public_ip_candidate(
    fetcher: Fetcher,
    *,
    existing: Sequence[AllowlistEntry] = (),
    found: Iterable[Candidate] = (),
) -> tuple[str | None, Candidate | None]:
    """``(public IP or None, Candidate unless the IP is already found or covered)``."""
    public = detect_public_ip(fetcher)
    if (
        public is None
        or public in {candidate.value for candidate in found}
        or Allowlist(existing).match(public, "ip") is not None
    ):
        return public, None
    return public, Candidate(public, PUBLIC_IP_REASON)
