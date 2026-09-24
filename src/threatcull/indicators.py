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

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_MAX_DOMAIN_LENGTH = 253
_MIN_LABELS = 2


@dataclass(frozen=True, slots=True)
class Indicator:
    value: str
    kind: IndicatorKind


def normalize(raw: str, source_kind: SourceKind) -> Indicator | None:
    """Return the canonical Indicator for ``raw``, or None if it is invalid or not public."""
    text = raw.strip()
    if not text:
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
    if network.prefixlen < min_prefix or not network.is_global:
        return None
    return Indicator(str(network), "cidr")


def _single_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Indicator | None:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global:
        return None
    return Indicator(str(address), "ip")


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
    if not all(_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        return None
    return Indicator(candidate, "domain")
