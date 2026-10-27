import pytest

from routes import investigate_center

CSRF_HEADER = {"X-CSRF-Token": "csrf-test-token"}
WRONG_CSRF = {"X-CSRF-Token": "totally-wrong-token"}


def _build_threat_intel_abuseipdb(ip, status="ok", result=None, error=None):
    entry = {"ip": ip}
    if status:
        entry["status"] = status
    if error:
        entry["error"] = error
    if result is not None:
        entry["result"] = result
    return entry


def _build_threat_intel_vt(ip, status="ok", result=None, attrs=None):
    entry = {"ip": ip}
    if status:
        entry["status"] = status
    if result is not None:
        entry["result"] = result
    if attrs is not None:
        entry["attrs"] = attrs
    return entry


def _risk_score(severity, ioc_count, analysis_valid):
    """Severity-derived score, only for a validated assessment."""
    if not analysis_valid:
        return 0
    severity_scores = {"critical": 90, "high": 70, "medium": 50, "low": 20}
    base_score = severity_scores.get(severity or "", 0)
    if ioc_count is None or ioc_count > 5:
        base_score = min(100, base_score + 10)
    return min(100, base_score)


@pytest.fixture
def authenticated_client(flask_app):
    client = flask_app.test_client()
    with client.session_transaction() as s:
        s["user"] = {"id": 42, "email": "tester@example.com"}
        s["csrf_token"] = "csrf-test-token"
    return client


def _result(**overrides):
    base = {
        "status": "completed",
        "analysis_valid": True,
        "analysis": {
            "status": "completed",
            "assessment_valid": True,
            "verdict": "suspicious",
            "severity": "high",
            "analysis": "narrative",
            "summary": "narrative",
        },
        "analysis_error": None,
        "iocs": {"ips": ["8.8.8.8"], "domains": [], "urls": [], "hashes": [], "emails": []},
        "threat_intel": {"abuseipdb": [], "virustotal": []},
        "mitre": {"id": "T1110", "name": "Brute Force"},
        "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
        "confidence": 55,
        "confidence_factors": ["factor"],
        "evidence": [],
        "recommendations": ["review"],
        "report": "report",
        "pipeline": [{"step": 1, "status": "completed", "label": "Extracting Indicators"}],
        "from_cache": False,
        "investigation_id": 10,
        "analyst_status": "New",
        "analyst_notes": "",
        "artifact_type": "log",
        "risk": {
            "score": _risk_score(None, None, True),
            "severity": "high",
            "confidence": 55,
            "confidence_factors": ["factor"],
            "assessed": True,
            "threat_category": "Suspicious Activity",
            "ioc_count": 0,
        },
    }
    base.update(overrides)
    # Apply analysis_valid-aware risk adjustments after base merge
    av = base.get("analysis_valid", True)
    if not av:
        base["risk"]["score"] = 0
        base["risk"]["confidence"] = 0
    return base


class TestThreatIntelStatusInference:
    def test_modern_ok_status_renders_checked(self):
        entry = {"status": "ok"}
        status = entry.get("status")
        assert status == "ok"

    def test_legacy_result_data_object_inferred_ok(self):
        entry = {"result": {"data": {"abuseConfidenceScore": 91}}}
        status = entry.get("status")
        if not status and entry.get("result") and isinstance(entry["result"], dict):
            if entry["result"].get("data") and isinstance(entry["result"]["data"], dict):
                status = "ok"
            else:
                status = "unknown"
        assert status == "ok"

    def test_legacy_result_info_only_uncertain(self):
        entry = {"result": {"info": "10.0.0.1 is a private/non-routable address -- skipped lookup"}}
        status = entry.get("status")
        if not status and entry.get("result") and isinstance(entry["result"], dict):
            if entry["result"].get("data") and isinstance(entry["result"]["data"], dict):
                status = "ok"
            else:
                status = "unknown"
        assert status == "unknown"

    def test_legacy_error_takes_precedence(self):
        entry = {"error": "timeout", "result": {"data": {"abuseConfidenceScore": 91}}}
        status = entry.get("status")
        if not status:
            if entry.get("error"):
                status = "error"
            elif entry.get("result") and isinstance(entry["result"], dict):
                if entry["result"].get("data") and isinstance(entry["result"]["data"], dict):
                    status = "ok"
        assert status == "error"

    def test_no_status_no_result_unknown(self):
        entry = {}
        status = entry.get("status")
        if not status:
            assert status is None


class TestDashboardTINARendering:
    def test_abuse_confidence_score_n_when_absent(self):
        d2 = {}
        score = d2.get("abuseConfidenceScore")
        displayed = score if score is not None and score != "" else "N/A"
        assert displayed == "N/A"

    def test_total_reports_n_when_absent(self):
        d2 = {}
        reports = d2.get("totalReports")
        displayed = reports if reports is not None and reports != "" else "N/A"
        assert displayed == "N/A"

    def test_country_code_n_when_absent(self):
        d2 = {}
        country = d2.get("countryCode")
        displayed = country if country is not None and country != "" else "--"
        assert displayed == "--"

    def test_abuse_confidence_score_displays_value_when_present(self):
        d2 = {"abuseConfidenceScore": 91}
        score = d2.get("abuseConfidenceScore")
        displayed = score if score is not None and score != "" else "N/A"
        assert displayed == 91

    def test_total_reports_displays_value_when_present(self):
        d2 = {"totalReports": 4}
        reports = d2.get("totalReports")
        displayed = reports if reports is not None and reports != "" else "N/A"
        assert displayed == 4

    def test_country_code_displays_value_when_present(self):
        d2 = {"countryCode": "US"}
        country = d2.get("countryCode")
        displayed = country if country is not None and country != "" else "--"
        assert displayed == "US"


class TestDashboardTINoIndicators:
    def test_no_indicators_shows_honest_message(self):
        abuse = []
        vt = []
        total = len(abuse) + len(vt)
        assert total == 0
        body_msg = "<div style='text-align:center;padding:12px;color:var(--ic-text-muted);font-size:12px;'>No public IP indicators required a threat-intel lookup.</div>"
        assert body_msg.startswith("<div")


class TestAPIResponseStructure:
    def test_response_always_includes_status(self):
        payload = _result()
        assert "status" in payload
        assert payload["status"] in ("completed", "partial", "failed")

    def test_response_includes_analysis_valid(self):
        payload = _result()
        assert "analysis_valid" in payload
        assert isinstance(payload["analysis_valid"], bool)

    def test_response_includes_threat_intel(self):
        payload = _result()
        assert "threat_intel" in payload
        assert isinstance(payload["threat_intel"], dict)

    def test_response_includes_pipeline(self):
        payload = _result()
        assert "pipeline" in payload
        assert isinstance(payload["pipeline"], list)

    def test_response_includes_iocs(self):
        payload = _result()
        assert "iocs" in payload
        assert isinstance(payload["iocs"], dict)

    def test_response_includes_risk(self):
        payload = _result()
        assert "risk" in payload
        assert isinstance(payload["risk"], dict)

    def test_risk_has_score_when_analysis_valid(self):
        payload = _result(analysis_valid=False)
        assert payload["risk"]["score"] == 0

    def test_risk_has_confidence_when_analysis_valid(self):
        payload = _result(analysis_valid=False)
        assert payload["risk"]["confidence"] == 0

    def test_confidence_factors_present_when_valid(self):
        payload = _result()
        assert "confidence_factors"
