# SPDX-License-Identifier: AGPL-3.0-only
"""Indicator normalisation: turn raw strings from Sources into canonical Indicators."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

IndicatorKind = Literal["ip", "cidr", "domain"]
SourceKind = Literal["ip", "domain"]

# Networks broader than these are never Indicators: one bad upstream line must not
# be able to block a meaningful share of the internet.
IPV4_MIN_PREFIX = 8
IPV6_MIN_PREFIX = 16

_Address = ipaddress.IPv4Address | ipaddress.IPv6Address

# IANA special-purpose ranges (RFC 6890 and successors). Anything overlapping one of
# these is never an Indicator, even when its endpoints are global addresses.
_SPECIAL_PURPOSE: dict[int, tuple[str, ...]] = {
    4: (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    ),
    6: (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ),
}
# version -> ((first address, last address) as ints, ...) for fast overlap tests.
_SPECIAL_BOUNDS: dict[int, tuple[tuple[int, int], ...]] = {
    version: tuple(
        (int(net.network_address), int(net.broadcast_address))
        for net in map(ipaddress.ip_network, ranges)
    )
    for version, ranges in _SPECIAL_PURPOSE.items()
}

# Used with fullmatch: "$" alone also matches before a trailing newline.
_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
# Whitespace or control characters inside a value (after trimming the ends) would
# become extra lines in a published Output.
_INNER_SPACE_OR_CONTROL = re.compile(r"[\s\x00-\x1f\x7f]")
_MAX_DOMAIN_LENGTH = 253
_MIN_LABELS = 2


@dataclass(frozen=True, slots=True)
class Indicator:
    value: str
    kind: IndicatorKind


def normalize(raw: str, source_kind: SourceKind) -> Indicator | None:
    """Return the canonical Indicator for ``raw``, or None if it is invalid or not public."""
    text = raw.strip()
    if not text or _INNER_SPACE_OR_CONTROL.search(text):
        return None
    if source_kind == "ip":
        return _normalize_ip(text)
    return _normalize_domain(text)


def _normalize_ip(text: str) -> Indicator | None:
    try:
        if "/" not in text:
            return _single_address(ipaddress.ip_address(text))
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if network.num_addresses == 1:
        return _single_address(network.network_address)
    min_prefix = IPV4_MIN_PREFIX if isinstance(network, ipaddress.IPv4Network) else IPV6_MIN_PREFIX
    if (
        network.prefixlen < min_prefix
        or not network.is_global
        or _is_special(
            network.version, int(network.network_address), int(network.broadcast_address)
        )
    ):
        return None
    return Indicator(str(network), "cidr")


def _single_address(address: _Address) -> Indicator | None:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    value = int(address)
    if not address.is_global or _is_special(address.version, value, value):
        return None
    return Indicator(str(address), "ip")


def _is_special(version: int, first: int, last: int) -> bool:
    """True if the addresses ``first``..``last`` overlap any IANA special-purpose range."""
    return any(first <= end and last >= start for start, end in _SPECIAL_BOUNDS[version])


def _normalize_domain(text: str) -> Indicator | None:
    candidate = text.lower().rstrip(".").removeprefix("*.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = candidate.split(".")
    if len(candidate) > _MAX_DOMAIN_LENGTH or len(labels) < _MIN_LABELS:
        return None
    if not all(_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        return None
    return Indicator(candidate, "domain")
