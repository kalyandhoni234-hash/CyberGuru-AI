"""Tests for detection rule generation (Sigma / YARA) and export."""

import pytest

from utils.rule_generator import generate_sigma_rule, generate_yara_rule, stable_uuid

CSRF_HEADER = {"X-CSRF-Token": "csrf-test-token"}


def _row(**overrides):
    row = {
        "id": 7,
        "artifact_hash": "abc123",
        "verdict": "likely_malicious",
        "severity": "high",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "iocs": {
            "ips": ["45.77.65.211"],
            "domains": ["evil.example"],
            "urls": ["http://evil.example/payload"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
            "emails": [],
        },
    }
    row.update(overrides)
    return row


class TestSigma:
    def test_includes_iocs_and_technique(self):
        rule = generate_sigma_rule(_row())
        assert "title: CyberGuru" in rule
        assert "45.77.65.211" in rule
        assert "evil.example" in rule
        assert "attack.t1110" in rule
        assert "Brute Force" in rule

    def test_condition_only_lists_present_selections(self):
        row = _row(iocs={"ips": ["1.2.3.4"]})
        rule = generate_sigma_rule(row)
        assert "selection_ip or selection_domain" not in rule
        assert "selection_ip" in rule
        assert "net.source.ip" in rule

    def test_no_iocs_produces_valid_fallback(self):
        rule = generate_sigma_rule(_row(iocs={}))
        assert "selection_artifact" in rule

    def test_level_maps_from_severity(self):
        assert "level: high" in generate_sigma_rule(_row(severity="high"))
        assert "level: critical" in generate_sigma_rule(_row(severity="critical"))

    def test_stable_id_is_deterministic(self):
        a = generate_sigma_rule(_row())
        b = generate_sigma_rule(_row())
        import re
        id_a = re.search(r"^id: (\S+)$", a, re.M).group(1)
        id_b = re.search(r"^id: (\S+)$", b, re.M).group(1)
        assert id_a == id_b


class TestYara:
    def test_includes_strings_for_each_ioc(self):
        rule = generate_yara_rule(_row())
        assert 'rule CyberGuru_Investigation_7' in rule
        assert '$ip_1 = "45.77.65.211"' in rule
        assert '$domain_1 = "evil.example"' in rule
        assert '$url_1 = "http://evil.example/payload"' in rule
        assert 'severity = "high"' in rule
        assert "attack.mitre.org/techniques/T1110" in rule

    def test_escapes_quotes_and_backslashes(self):
        row = _row(iocs={"ips": ['1.2.3.4"x'], "hashes": ["a\\b"]})
        rule = generate_yara_rule(row)
        assert '\\"' in rule
        assert "\\\\" in rule

    def test_no_iocs_gets_placeholder(self):
        rule = generate_yara_rule(_row(iocs={}))
        assert "$placeholder" in rule
        assert "any of them" in rule


class TestStableUuid:
    def test_is_uuid_shaped(self):
        out = stable_uuid("x")
        assert len(out) == 36
        assert out.count("-") == 4

    def test_deterministic(self):
        assert stable_uuid("seed") == stable_uuid("seed")
        assert stable_uuid("seed") != stable_uuid("other")


@pytest.fixture
def authed(flask_app):
    client = flask_app.test_client()
    with client.session_transaction() as s:
        s["user"] = {"id": 42, "email": "tester@example.com"}
        s["csrf_token"] = "csrf-test-token"
    return client


class TestExportEndpoint:
    def test_sigma_export(self, authed, monkeypatch):
        from routes import investigate_center
        monkeypatch.setattr(
            investigate_center,
            "get_investigation_by_id",
            lambda *a, **k: _row(),
        )
        resp = authed.get("/api/investigate/7/export/rule/sigma")
        assert resp.status_code == 200
        assert resp.mimetype == "text/yaml"
        assert "title: CyberGuru" in resp.get_data(as_text=True)
        assert "attachment" in resp.headers["Content-Disposition"]

    def test_yara_export(self, authed, monkeypatch):
        from routes import investigate_center
        monkeypatch.setattr(
            investigate_center,
            "get_investigation_by_id",
            lambda *a, **k: _row(),
        )
        resp = authed.get("/api/investigate/7/export/rule/yara")
        assert resp.status_code == 200
        assert resp.mimetype == "text/x-yara"
        assert "rule CyberGuru_Investigation_7" in resp.get_data(as_text=True)

    def test_unknown_format_returns_400(self, authed, monkeypatch):
        from routes import investigate_center
        monkeypatch.setattr(
            investigate_center,
            "get_investigation_by_id",
            lambda *a, **k: _row(),
        )
        resp = authed.get("/api/investigate/7/export/rule/snort")
        assert resp.status_code == 400

    def test_missing_investigation_returns_404(self, authed, monkeypatch):
        from routes import investigate_center
        monkeypatch.setattr(
            investigate_center, "get_investigation_by_id", lambda *a, **k: None
        )
        resp = authed.get("/api/investigate/999/export/rule/sigma")
        assert resp.status_code == 404
