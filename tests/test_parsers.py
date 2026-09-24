# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from threatcull.parsers import ParseError, parse


def test_plain_takes_first_token_and_skips_comments() -> None:
    text = "# header\n; note\n// c-style\n\n1.2.3.4\t7\n5.6.7.8 # inline\n"
    assert list(parse("plain", text)) == ["1.2.3.4", "5.6.7.8"]


def test_hosts_yields_every_hostname_and_skips_loopback_names() -> None:
    text = (
        "127.0.0.1 localhost\n"
        "0.0.0.0 0.0.0.0\n"
        "0.0.0.0 bad.example.com\n"
        "0.0.0.0 a.example.net b.example.net\n"
        "single.example.org\n"
    )
    assert list(parse("hosts", text)) == [
        "bad.example.com",
        "a.example.net",
        "b.example.net",
        "single.example.org",
    ]


def test_adblock_extracts_plain_domain_rules_only() -> None:
    text = (
        "! Title: demo\n"
        "||ads.example.com^\n"
        "||track.example.net^$third-party\n"
        "@@||good.example.com^\n"
        "example.org##.banner\n"
        "||wild*.example.com^\n"
        "||path.example.com/ads^\n"
    )
    assert list(parse("adblock", text)) == ["ads.example.com", "track.example.net"]


def test_csv_reads_the_configured_column_and_skips_comment_rows() -> None:
    text = '#ip,ioc\n1.2.3.4,Cobalt Strike\n"5.6.7.8",Sliver\n\n'
    assert list(parse("csv", text)) == ["1.2.3.4", "5.6.7.8"]
    assert list(parse("csv", text, csv_column=1)) == ["Cobalt Strike", "Sliver"]


def test_csv_ignores_rows_shorter_than_the_column() -> None:
    assert list(parse("csv", "only-one\n", csv_column=3)) == []


def test_json_reads_lists_under_the_given_keys() -> None:
    text = '{"addresses": ["23.235.32.0/20"], "ipv6_addresses": ["2a04:4e40::/32"], "x": 1}'
    got = list(parse("json", text, json_keys=("addresses", "ipv6_addresses")))
    assert got == ["23.235.32.0/20", "2a04:4e40::/32"]


@pytest.mark.parametrize("text", ["not json", "[1, 2]", '{"addresses": "1.2.3.4"}'])
def test_json_rejects_malformed_content(text: str) -> None:
    with pytest.raises(ParseError):
        list(parse("json", text, json_keys=("addresses",)))
