"""Mocked provider tests for AbuseIPDB / VirusTotal lookups.

No live external request is made. Each test asserts both the returned status
and that failures are not presented as clean intelligence.
"""

import requests

import utils.abuseipdb_tool as abuse
import utils.virustotal_tool as vt


class FakeResponse:
    def __init__(self, status_code=200, json_body=None, json_error=False):
        self.status_code = status_code
        self._json_body = json_body
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("invalid json")
        return self._json_body


def test_private_ip_is_never_sent_to_provider(monkeypatch):
    monkeypatch.setattr(
        abuse.requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call network")),
    )
    result = abuse.check_abuseipdb("10.0.0.5")
    assert result["status"] == "not_applicable"
    assert "Private" in result["reason"]


def test_invalid_ip_is_not_applicable(monkeypatch):
    monkeypatch.setattr(
        abuse.requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call network")),
    )
    assert abuse.check_abuseipdb("not-an-ip")["status"] == "not_applicable"


def test_abuseipdb_success_is_cached(monkeypatch):
    calls = {}
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setattr(abuse, "set_abuseipdb_cached", lambda ip, value: calls.setdefault("cached", (ip, value)))
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(
        abuse.requests,
        "get",
        lambda *a, **k: FakeResponse(json_body={"data": {"abuseConfidenceScore": 91}}),
    )

    result = abuse.check_abuseipdb("8.8.8.8")
    assert result["status"] == "ok"
    assert result["data"]["abuseConfidenceScore"] == 91
    assert calls["cached"][0] == "8.8.8.8"


def test_cached_value_is_returned_without_request(monkeypatch):
    monkeypatch.setattr(
        abuse,
        "get_abuseipdb_cached",
        lambda ip: {"data": {"abuseConfidenceScore": 40}},
    )
    monkeypatch.setattr(
        abuse.requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("cache should short-circuit")),
    )

    result = abuse.check_abuseipdb("8.8.8.8")
    assert result["status"] == "ok"
    assert result["cached"] is True


def test_missing_credentials_are_a_configuration_error(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = abuse.check_abuseipdb("8.8.8.8")
    assert result["status"] == "error"
    assert result["error_code"] == "configuration"
    assert "test-key" not in str(result)


def test_authentication_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "secret-key")
    monkeypatch.setattr(abuse.requests, "get", lambda *a, **k: FakeResponse(status_code=401))

    result = abuse.check_abuseipdb("8.8.8.8")
    assert result["status"] == "error"
    assert result["error_code"] == "authentication"
    assert "secret-key" not in str(result)


def test_rate_limit_and_provider_outage(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    monkeypatch.setattr(abuse.requests, "get", lambda *a, **k: FakeResponse(status_code=429))
    assert abuse.check_abuseipdb("8.8.8.8")["error_code"] == "rate_limited"

    monkeypatch.setattr(abuse.requests, "get", lambda *a, **k: FakeResponse(status_code=503))
    assert abuse.check_abuseipdb("8.8.8.8")["error_code"] == "unavailable"


def test_timeout_and_network_error(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def raise_timeout(*a, **k):
        raise requests.exceptions.Timeout()

    monkeypatch.setattr(abuse.requests, "get", raise_timeout)
    assert abuse.check_abuseipdb("8.8.8.8")["error_code"] == "timeout"

    def raise_network(*a, **k):
        raise requests.exceptions.ConnectionError()

    monkeypatch.setattr(abuse.requests, "get", raise_network)
    assert abuse.check_abuseipdb("8.8.8.8")["error_code"] == "unavailable"


def test_malformed_response_is_not_clean(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(
        abuse.requests,
        "get",
        lambda *a, **k: FakeResponse(json_error=True),
    )

    result = abuse.check_abuseipdb("8.8.8.8")
    assert result["status"] == "error"
    assert result["error_code"] == "malformed_response"


def test_abuseipdb_404_is_not_found_not_clean(monkeypatch):
    monkeypatch.setattr(abuse, "get_abuseipdb_cached", lambda ip: None)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(abuse.requests, "get", lambda *a, **k: FakeResponse(status_code=404))

    assert abuse.check_abuseipdb("8.8.8.8")["status"] == "not_found"


def test_virustotal_supports_both_documented_env_names(monkeypatch):
    seen = {}
    monkeypatch.setattr(vt, "get_virustotal_cached", lambda ip: None)
    monkeypatch.setattr(vt, "set_virustotal_cached", lambda ip, value: None)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-doc-key")

    def fake_get(url, headers=None, **kwargs):
        seen["key"] = headers.get("x-apikey")
        return FakeResponse(json_body={"data": {"attributes": {}}})

    monkeypatch.setattr(vt.requests, "get", fake_get)
    assert vt.check_virustotal_ip("8.8.8.8")["status"] == "ok"
    assert seen["key"] == "vt-doc-key"


def test_virustotal_malformed_payload_is_error(monkeypatch):
    monkeypatch.setattr(vt, "get_virustotal_cached", lambda ip: None)
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(
        vt.requests,
        "get",
        lambda *a, **k: FakeResponse(json_error=True),
    )

    result = vt.check_virustotal_ip("8.8.8.8")
    assert result["status"] == "error"
    assert result["error_code"] == "malformed_response"
