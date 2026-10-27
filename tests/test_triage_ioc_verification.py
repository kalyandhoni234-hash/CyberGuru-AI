"""Tests for IOC verification statuses in the triage pipeline.

Covers the "tool-driven + scope fallback" model:
  - IPs checked via threat-intel tools take the tool's status
  - unchecked IPs fall back to a scope-derived status
  - non-IP IOCs (domains/hashes/urls/emails) are always not_applicable
  - RFC 5737 TEST-NET addresses are not_applicable even though Python's
    ipaddress marks them is_private (not is_reserved)
"""

from services.triage_service import _extract_verified_iocs
from utils.ioc_extractor import SCOPE_REASONS


def test_global_ip_without_tool_lookup_is_unverified():
    """Prose mention alone is not verification: no provider was queried."""
    iocs = _extract_verified_iocs("C2 at 8.8.8.8", tool_results={})
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["verification"] == "unverified"
    assert "no threat-intel lookup" in iocs[0]["note"].lower()


def test_testnet_ip_without_tool_lookup_is_not_applicable():
    iocs = _extract_verified_iocs("Docs example 203.0.113.77", tool_results={})
    assert iocs[0]["verification"] == "not_applicable"
    assert iocs[0]["note"] == SCOPE_REASONS["documentation"]


def test_private_ip_without_tool_lookup_is_not_applicable():
    iocs = _extract_verified_iocs("Internal host 10.0.0.5", tool_results={})
    assert iocs[0]["verification"] == "not_applicable"


def test_tool_ok_status_is_preserved():
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "ok", "data": {}}},
    )
    assert iocs[0]["verification"] == "ok"


def test_tool_not_found_status_is_preserved():
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "not_found", "message": "No results"}},
    )
    assert iocs[0]["verification"] == "not_found"


def test_tool_error_status_is_preserved():
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "error", "error": "API key missing"}},
    )
    assert iocs[0]["verification"] == "error"


def test_tool_not_applicable_beats_scope_fallback():
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "not_applicable", "reason": "blocked"}},
    )
    assert iocs[0]["verification"] == "not_applicable"
    assert iocs[0]["note"] == "blocked"


def test_domains_hashes_urls_emails_are_not_applicable():
    iocs = _extract_verified_iocs(
        "evil.example, https://evil.example/p, d41d8cd98f00b204e9800998ecf8427e, "
        "analyst@example.com",
        tool_results={},
    )
    by_type = {ioc["type"]: ioc for ioc in iocs}
    assert by_type["domain"]["verification"] == "not_applicable"
    assert "no verification path" in by_type["domain"]["note"].lower()
    assert by_type["hash"]["verification"] == "not_applicable"
    assert by_type["url"]["verification"] == "not_applicable"
    assert by_type["email"]["verification"] == "not_applicable"


def test_every_referenced_ioc_is_present_never_dropped():
    iocs = _extract_verified_iocs(
        "203.0.113.77, 8.8.8.8, evil.example",
        tool_results={},
    )
    assert {ioc["value"] for ioc in iocs} == {"203.0.113.77", "8.8.8.8", "evil.example"}


def test_tool_checked_ip_appears_even_if_absent_from_prose():
    iocs = _extract_verified_iocs(
        "no ips mentioned",
        tool_results={"198.51.100.42": {"status": "ok", "data": {}}},
    )
    assert iocs[0]["value"] == "198.51.100.42"
    assert iocs[0]["verification"] == "ok"


def test_tool_status_ok_is_high_confidence():
    """OK status should be preserved as high confidence."""
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "ok", "data": {}}},
    )
    assert iocs[0]["verification"] == "ok"
    assert iocs[0]["type"] == "ip"


def test_tool_status_not_applicable_no_increase_in_confidence():
    """Ensure not_applicable status does not inflate confidence."""
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "not_applicable", "reason": "private IP"}},
    )
    assert iocs[0]["verification"] == "not_applicable"


def test_tool_status_not_found_no_increase_in_confidence():
    """Ensure not_found status does not inflate confidence."""
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "not_found", "message": "No results"}},
    )
    assert iocs[0]["verification"] == "not_found"


def test_tool_status_error_no_increase_in_confidence():
    """Ensure error status does not inflate confidence."""
    iocs = _extract_verified_iocs(
        "Check 8.8.8.8",
        tool_results={"8.8.8.8": {"status": "error", "error": "API key missing"}},
    )
    assert iocs[0]["verification"] == "error"


def test_private_ip_is_not_applicable_in_triage():
    """Private IPs should be marked not_applicable even in tool results when not explicitly looked up."""
    # When there's no tool lookup (tool_results empty), private IPs from prose are not_applicable
    iocs = _extract_verified_iocs(
        "Internal host 10.0.0.5",
        tool_results={},
    )
    assert iocs[0]["verification"] == "not_applicable"


def test_testnet_ip_is_not_applicable():
    """RFC 5737 TEST-NET addresses should be not_applicable."""
    iocs = _extract_verified_iocs(
        "Docs example 203.0.113.77",
        tool_results={},
    )
    assert iocs[0]["verification"] == "not_applicable"
    assert iocs[0]["note"] == SCOPE_REASONS["documentation"]