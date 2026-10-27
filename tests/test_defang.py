"""Defanging edge cases: presentation-layer neutralisation must never
corrupt indicator values or feed defanged text to provider APIs."""

import pytest

from utils.defang import (defang_domain, defang_email, defang_hash, defang_ip,
                           defang_iocs, defang_url)
from utils.abuseipdb_tool import check_abuseipdb


def test_defang_ip_neutralises_dots():
    assert defang_ip("45.77.65.211") == "45[.]77[.]65[.]211"


def test_defang_ip_leaves_ipv6_text_intact():
    # IPv6 has no dots to neutralise; the value must pass through unharmed
    # (no accidental mangling of an address we may still need internally).
    assert defang_ip("2001:db8::1") == "2001:db8::1"


def test_defang_url_scheme_and_host():
    out = defang_url("https://evil.example/path?a=1")
    assert out.startswith("hxxps[://]evil[.]example")
    assert "://evil.example" not in out


def test_defang_email():
    assert defang_email("user@evil.example") == "user[@]evil[.]example"


def test_defang_domain_and_hash():
    assert defang_domain("evil.example") == "evil[.]example"
    assert defang_hash("d41d8cd98f00b204e9800998ecf8427e") == \
        "d41d8cd98f00b204e9800998ecf8427e"


def test_defang_iocs_handles_malformed_input():
    # Non-dict, missing keys, non-list values, and junk items must not crash
    # export rendering or invent values.
    assert defang_iocs(None) == {"ips": [], "domains": [], "urls": [],
                                 "hashes": [], "emails": []}
    assert defang_iocs({"ips": "not-a-list"})["ips"] == []
    out = defang_iocs({"ips": [123, None, "1.2.3.4"]})
    # int values are stringified, None/junk dropped — nothing invented.
    assert "1[.]2[.]3[.]4" in out["ips"]
    assert "123" in out["ips"]
    assert len(out["ips"]) == 2


def test_original_dict_is_not_mutated():
    original = {"ips": ["1.2.3.4"], "domains": [], "urls": [],
                "hashes": [], "emails": []}
    defang_iocs(original)
    assert original["ips"] == ["1.2.3.4"]


def test_defanged_ip_never_reaches_the_provider(monkeypatch):
    """A defanged value must be rejected before any network call — it can
    only arrive from presentation-layer text, never from a lookup path."""
    def _fail(*a, **k):
        pytest.fail("provider API must not be called with a defanged IP")

    monkeypatch.setattr("utils.abuseipdb_tool.requests.get", _fail)
    result = check_abuseipdb("45[.]77[.]65[.]211")
    assert result["status"] == "not_applicable"
    assert "result" not in result
