# SPDX-License-Identifier: AGPL-3.0-only
"""The fast domain normaliser (#61) must accept and reject exactly what the old one did."""

import ipaddress
import random
import re
import string

import pytest

from threatcull.indicators import Indicator, normalize

_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")


def _reference_domain(text: str) -> Indicator | None:
    """The 2.3.1 implementation, kept verbatim as the oracle."""
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
    if len(candidate) > 253 or len(labels) < 2:
        return None
    if not all(_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        return None
    return Indicator(candidate, "domain")


def _reference(raw: str) -> Indicator | None:
    text = raw.strip()
    if not text or re.search(r"[\s\x00-\x1f\x7f]", text):
        return None
    return _reference_domain(text)


EDGE_CASES = [
    "example.com",
    "EXAMPLE.COM.",
    "*.example.com",
    "a..b.com",
    ".example.com",
    "example.com..",
    "a" * 63 + ".com",
    "a" * 64 + ".com",
    "x." * 126 + "co",
    "x." * 127 + "co",
    "-bad.com",
    "bad-.com",
    "under_score.com",
    "123.456",
    "1.2.3.4",
    "1.2.3.4.",
    "01.2.3.4",
    "::1",
    "2001:db8::1",
    "fe80::1%eth0",
    "[::1]",
    "1.2.3",
    "\uff11\uff12\uff13.com",
    "²³.com",
    "١٢٣.١٢٣",
    "bücher.de",
    "xn--bcher-kva.de",
    "xn--.com",
    "münchen..de",
    "ПРИМЕР.РФ",
    "例え.テスト",
    "a.b",
    "a",
    "",
    ".",
    "*.",
    "com.123",
    "example.123",
    "a.b.c.d.e.f",
    "ex ample.com",
    "ex\x00ample.com",
    "ex\u200bample.com",
    "ex\u2028ample.com",
    "\ufeffexample.com",
    "example.com\n",
    "éxample.com",
    "ß.de",
    "İstanbul.tr",
    "K.com",
    "ꓘ.com",
]


@pytest.mark.parametrize("raw", EDGE_CASES)
def test_edge_cases_match_the_reference(raw: str) -> None:
    assert normalize(raw, "domain") == _reference(raw)


def test_random_inputs_match_the_reference() -> None:
    rng = random.Random(61)  # noqa: S311 - a fixed seed for a repeatable test
    unusual = "\u00fc\u00df\u0130\u0661\u00b2\uff11\u200b\x00\t"  # IDN, digits, controls
    alphabet = string.ascii_letters + string.digits + ".-_:*%[] " + unusual
    for _ in range(200_000):
        raw = "".join(rng.choices(alphabet, k=rng.randint(0, 40)))
        assert normalize(raw, "domain") == _reference(raw), repr(raw)
