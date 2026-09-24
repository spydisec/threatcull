# SPDX-License-Identifier: AGPL-3.0-only
"""Fast Allowlist matching for IPs, CIDRs (containment and overlap) and domain suffixes."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from threatcull.indicators import IndicatorKind
from threatcull.store.allowlist import AllowlistEntry

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class Allowlist:
    def __init__(self, entries: Iterable[AllowlistEntry]) -> None:
        self._domains: dict[str, AllowlistEntry] = {}
        # version -> prefix length -> network address as int -> entry
        self._prefixes: dict[int, dict[int, dict[int, AllowlistEntry]]] = {4: {}, 6: {}}
        self._networks: list[tuple[_Network, AllowlistEntry]] = []
        for entry in entries:
            if entry.kind == "domain":
                self._domains.setdefault(entry.value, entry)
                continue
            network = ipaddress.ip_network(entry.value)
            by_prefix = self._prefixes[network.version].setdefault(network.prefixlen, {})
            by_prefix.setdefault(int(network.network_address), entry)
            self._networks.append((network, entry))

    def match(self, value: str, kind: IndicatorKind) -> AllowlistEntry | None:
        """Return the Allowlist entry that excludes this Indicator, if any."""
        if kind == "domain":
            labels = value.split(".")
            for start in range(len(labels) - 1):
                hit = self._domains.get(".".join(labels[start:]))
                if hit is not None:
                    return hit
            return None
        network = ipaddress.ip_network(value)
        covering = self._covering(network)
        if covering is not None or kind == "ip":
            return covering
        return self._inside(network)

    def _covering(self, network: _Network) -> AllowlistEntry | None:
        bits = network.max_prefixlen
        address = int(network.network_address)
        for prefixlen, by_address in self._prefixes[network.version].items():
            if prefixlen > network.prefixlen:
                continue
            shift = bits - prefixlen
            hit = by_address.get(address >> shift << shift)
            if hit is not None:
                return hit
        return None

    def _inside(self, network: _Network) -> AllowlistEntry | None:
        for candidate, entry in self._networks:
            if (
                isinstance(network, ipaddress.IPv4Network)
                and isinstance(candidate, ipaddress.IPv4Network)
                and candidate.subnet_of(network)
            ) or (
                isinstance(network, ipaddress.IPv6Network)
                and isinstance(candidate, ipaddress.IPv6Network)
                and candidate.subnet_of(network)
            ):
                return entry
        return None
