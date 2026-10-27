"""Phase 0 regression tests for the investigation orchestration contract.

These tests exercise the real ``services.cyberguru_agent`` module (the test
harness no longer replaces it with a stub). Gemini is faked at the
``analyze_artifact`` boundary so no network or credentials are required.
"""

import pytest

import services.cyberguru_agent as agent


def _analysis(**overrides):
    base = {
        "analysis": "Verdict: suspicious\nEvidence: repeated failures.",
        "artifact_type": "auto",
        "status": "completed",
        "assessment_valid": True,
        "error_code": None,
        "error": None,
        "verdict": "suspicious",
        "severity": "high",
        "iocs": [],
        "tool_calls": [],
        "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
    }
    base.update(overrides)
    return base


def test_valid_analysis_completes_with_real_stage_states(monkeypatch):
    monkeypatch.setattr(agent, "analyze_artifact", lambda *a, **k: _analysis())

    result = agent.investigate("failed login from 8.8.8.8", artifact_type="log")

    assert result["status"] == "completed"
    assert result["analysis_valid"] is True
    assert result["analysis"]["verdict"] == "suspicious"
    assert result["confidence"] > 0
    assert result["pipeline"][0]["status"] == "completed"
    assert result["pipeline"][1]["status"] == "completed"
    # Pipeline stage 2 now shows the actual IOC extraction detail rather than a hardcoded artifact type
    assert result["pipeline"][1]["detail"] == "1 indicator(s) extracted."
    # No tool calls: the threat-intel stage is skipped, never reported done.
    assert result["pipeline"][2]["status"] == "skipped"
    assert result["pipeline"][3]["status"] == "completed"
    assert result["pipeline"][5]["status"] == "completed"
    assert result["pipeline"][6]["status"] == "completed"


def test_ai_failure_produces_failed_status_and_no_verdict(monkeypatch):
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: {
            "analysis": None,
            "artifact_type": "auto",
            "status": "error",
            "assessment_valid": False,
            "error_code": "timeout",
            "error": "AI analysis could not be completed.",
            "verdict": None,
            "severity": None,
            "iocs": [],
            "tool_calls": [],
            "mitre_techniques": [],
        },
    )

    result = agent.investigate("some evidence")

    assert result["status"] == "failed"
    assert result["analysis_valid"] is False
    assert result["analysis"]["verdict"] is None
    assert result["confidence"] == 0
    assert result["pipeline"][4]["status"] == "failed"
    assert result["pipeline"][5]["status"] == "failed"
    assert "unavailable" in result["recommendations"][0].lower()
    assert "unknown" in result["report"].lower()


def test_invalid_model_output_is_a_failure_not_inconclusive(monkeypatch):
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: {
            "analysis": "I think it might be suspicious.",
            "artifact_type": "auto",
            "status": "invalid_output",
            "assessment_valid": False,
            "error_code": "missing_assessment_block",
            "error": "AI output did not contain a valid assessment block.",
            "verdict": None,
            "severity": None,
            "iocs": [],
            "tool_calls": [],
            "mitre_techniques": [],
        },
    )

    result = agent.investigate("evidence")
    assert result["status"] == "failed"
    assert result["analysis_valid"] is False
    assert result["analysis"]["status"] == "invalid_output"


def test_failed_threat_intel_stage_marks_overall_partial(monkeypatch):
    failed_lookup = {
        "name": "check_abuseipdb",
        "args": {"ip": "8.8.8.8"},
        "result": {
            "status": "error",
            "error_code": "timeout",
            "error": "Threat-intel lookup timed out.",
        },
    }
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: _analysis(tool_calls=[failed_lookup]),
    )

    result = agent.investigate("failed login from 8.8.8.8")

    assert result["status"] == "partial"
    assert result["pipeline"][2]["status"] == "failed"
    assert result["threat_intel"]["abuseipdb"][0]["status"] == "error"
    # A failed lookup is never rendered as a clean provider result.
    assert "failed" in result["report"].lower()


def test_private_ip_lookup_is_skipped_not_failed(monkeypatch):
    not_applicable = {
        "name": "check_abuseipdb",
        "args": {"ip": "10.0.0.5"},
        "result": {
            "status": "not_applicable",
            "ip": "10.0.0.5",
            "reason": "Private Network Range (RFC 1918)",
        },
    }
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: _analysis(tool_calls=[not_applicable]),
    )

    result = agent.investigate("internal host 10.0.0.5")
    assert result["status"] == "completed"
    assert result["pipeline"][2]["status"] == "skipped"


def test_artifact_type_is_propagated_and_validated(monkeypatch):
    captured = {}

    def fake_analyze(artifact, artifact_type="auto"):
        captured["type"] = artifact_type
        return _analysis(artifact_type=artifact_type)

    monkeypatch.setattr(agent, "analyze_artifact", fake_analyze)

    result = agent.investigate("payload", artifact_type="malware")
    assert captured["type"] == "malware"
    assert result["artifact_type"] == "malware"

    with pytest.raises(ValueError):
        agent.investigate("payload", artifact_type="not-a-type")


def test_repeated_tool_calls_do_not_duplicate_threat_intel(monkeypatch):
    call = {
        "name": "check_abuseipdb",
        "args": {"ip": "8.8.8.8"},
        "result": {"status": "ok", "ip": "8.8.8.8", "data": {"abuseConfidenceScore": 0}},
    }
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: _analysis(tool_calls=[call, dict(call)]),
    )

    result = agent.investigate("8.8.8.8")
    assert len(result["threat_intel"]["abuseipdb"]) == 1


def test_cache_hit_reconstructs_full_contract_without_calling_ai(monkeypatch):
    row = {
        "id": 77,
        "verdict": "suspicious",
        "severity": "high",
        "confidence": 55,
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "iocs": {"ips": ["8.8.8.8"], "domains": [], "urls": [], "hashes": [], "emails": []},
        "threat_intel": {"abuseipdb": [], "virustotal": []},
        "report": "stored report",
        "analysis_text": "stored narrative",
        "analysis_valid": True,
        "artifact_type": "log",
        "analysis_error": None,
        "analyst_status": "In Review",
        "analyst_notes": "reviewed",
    }
    monkeypatch.setattr(agent, "find_recent_investigation", lambda *a, **k: row)
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: pytest.fail("cache hit must not call the AI"),
    )

    result = agent.investigate("same artifact", user_id=42, artifact_type="log")

    assert result["from_cache"] is True
    assert result["investigation_id"] == 77
    assert result["status"] == "completed"
    assert result["analysis"]["summary"] == "stored narrative"
    assert result["analysis"]["verdict"] == "suspicious"
    assert result["analysis_valid"] is True
    assert result["pipeline"]
    assert result["recommendations"]
    assert result["analyst_status"] == "In Review"


def test_unauthenticated_requests_are_never_cached(monkeypatch):
    monkeypatch.setattr(
        agent,
        "find_recent_investigation",
        lambda *a, **k: pytest.fail("anonymous requests must not read the cache"),
    )
    monkeypatch.setattr(agent, "analyze_artifact", lambda *a, **k: _analysis())

    result = agent.investigate("evidence", user_id=None)
    assert result["from_cache"] is False
    assert result["investigation_id"] is None


def test_malformed_stored_row_reconstructs_safely():
    result = agent.result_from_db_row(
        {
            "id": 5,
            "iocs": ["not", "a", "dict"],
            "threat_intel": "not a dict",
            "verdict": "benign",
            "severity": "low",
            "confidence": "not-a-number",
            "analysis_valid": False,
            "analysis_error": "invalid_output",
            "report": None,
        }
    )

    assert result["analysis_valid"] is False
    assert result["confidence"] == 0
    assert result["iocs"] == {}
    assert result["status"] == "failed"
    assert result["pipeline"][6]["status"] == "failed"


def test_not_found_lookup_is_completed_not_silent(monkeypatch):
    """A provider answering 'no record' is a successful check: the stage is
    completed and the entry keeps its not_found status and message, so the
    UI can distinguish 'checked, nothing found' from 'never checked'."""
    not_found = {
        "name": "check_virustotal_ip",
        "args": {"ip": "203.0.113.9"},
        "result": {
            "status": "not_found",
            "ip": "203.0.113.9",
            "message": "No results found for this IP",
        },
    }
    monkeypatch.setattr(
        agent,
        "analyze_artifact",
        lambda *a, **k: _analysis(tool_calls=[not_found]),
    )

    result = agent.investigate("suspicious host 203.0.113.9")

    assert result["status"] == "completed"
    assert result["pipeline"][2]["status"] == "completed"
    entry = result["threat_intel"]["virustotal"][0]
    assert entry["status"] == "not_found"
    assert entry["message"] == "No results found for this IP"
