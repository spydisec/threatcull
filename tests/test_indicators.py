# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from threatcull.indicators import Indicator, normalize


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3.4", Indicator("1.2.3.4", "ip")),
        (" 8.8.8.8 ", Indicator("8.8.8.8", "ip")),
        ("1.2.3.4/32", Indicator("1.2.3.4", "ip")),
        ("45.9.20.0/24", Indicator("45.9.20.0/24", "cidr")),
        ("45.9.20.7/24", Indicator("45.9.20.0/24", "cidr")),
        ("2001:4860:4860::8888", Indicator("2001:4860:4860::8888", "ip")),
        ("::ffff:1.2.3.4", Indicator("1.2.3.4", "ip")),
    ],
)
def test_normalize_ip_accepts_public_addresses_and_networks(raw: str, expected: Indicator) -> None:
    assert normalize(raw, "ip") == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not-an-ip",
        "01.2.3.4",
        "1.2.3.4:80",
        "10.0.0.1",
        "192.168.1.10",
        "127.0.0.1",
        "100.64.0.1",
        "2001:db8::1",
        "fe80::1",
        "0.0.0.0/0",
        "8.0.0.0/7",
        "10.0.0.0/8",
        "::/0",
    ],
)
def test_normalize_ip_rejects_invalid_private_and_oversized(raw: str) -> None:
    assert normalize(raw, "ip") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("Example.COM.", "example.com"),
        ("*.ads.example.net", "ads.example.net"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("_dmarc.example.org", "_dmarc.example.org"),
    ],
)
def test_normalize_domain_canonicalises(raw: str, expected: str) -> None:
    assert normalize(raw, "domain") == Indicator(expected, "domain")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "example",
        "1.2.3.4",
        "-bad.example.com",
        "exa mple.com",
        "example..com",
        "a" * 64 + ".com",
        "example.123",
        "http://example.com/x",
        "example.com:443",
    ],
)
def test_normalize_domain_rejects_invalid(raw: str) -> None:
    assert normalize(raw, "domain") is None


def test_case_and_trailing_dot_variants_are_one_indicator() -> None:
    variants = {normalize(v, "domain") for v in ("Example.COM.", "example.com", "*.example.com")}
    assert variants == {Indicator("example.com", "domain")}
