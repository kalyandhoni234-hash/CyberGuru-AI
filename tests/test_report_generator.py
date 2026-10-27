"""Regression tests for the incident report structure and honesty rules.

The stored report is the single source shared by the dashboard's Raw
Findings view and the Markdown export, so these tests pin its sections,
its defanged indicators, its threat-intel status lines, and the rule that
a failed assessment is never presented as a real verdict/severity.
"""

from utils.report_generator import generate_incident_report


def _iocs():
    return {"ips": ["45.77.65.211"], "domains": [], "urls": [], "hashes": [], "emails": []}


def _ti_ok_and_error():
    return {
        "abuseipdb": [
            {"ip": "45.77.65.211", "status": "ok",
             "result": {"status": "ok", "ip": "45.77.65.211",
                        "data": {"abuseConfidenceScore": 0, "totalReports": 0}}},
            {"ip": "9.9.9.9", "status": "error", "error_code": "timeout",
             "error": "Threat-intel lookup timed out."},
        ],
        "virustotal": [
            {"ip": "1.2.3.4", "status": "ok",
             "result": {"status": "ok", "ip": "1.2.3.4",
                        "data": {"attributes": {"last_analysis_stats":
                                                {"malicious": 0, "suspicious": 1}}}}},
        ],
    }


def test_report_contains_required_sections():
    report = generate_incident_report(
        verdict="suspicious", severity="low", iocs=_iocs(),
        mitre={"id": "T1110", "name": "Brute Force"},
        recommendations=["Correlate with surrounding log activity."],
        threat_intel=_ti_ok_and_error(),
        summary="Repeated authentication failures from one source.",
        artifact_type="log",
    )
    for section in ("INCIDENT REPORT", "EXECUTIVE SUMMARY",
                    "INDICATORS OF COMPROMISE (DEFANGED)", "THREAT INTELLIGENCE",
                    "VERDICT RATIONALE", "RECOMMENDATIONS", "REPORT METADATA"):
        assert section in report
    assert "Verdict: suspicious" in report
    assert "Severity: low" in report
    assert "Assessment: validated" in report
    assert "Repeated authentication failures" in report
    assert "Artifact type: log" in report
    # IOCs are defanged in the presentation layer.
    assert "45[.]77[.]65[.]211" in report
    assert "45.77.65.211" not in report


def test_failed_assessment_has_warning_and_unknown_verdict():
    report = generate_incident_report(
        verdict=None, severity=None, iocs=_iocs(), mitre=None,
        recommendations=["Automated assessment is unavailable — treat all "
                         "indicators as unverified."],
        threat_intel=None,
        analysis_error="timeout",
        summary="some raw narrative",
    )
    assert "WARNING: AI assessment unavailable" in report
    assert "Verdict: unknown" in report
    assert "Severity: unknown" in report
    assert "Assessment: unavailable" in report
    assert "Rationale unavailable" in report
    # An unvalidated narrative must be labelled as such.
    assert "UNVALIDATED AI NARRATIVE (not an assessment" in report
    assert "some raw narrative" in report


def test_ti_error_and_ok_results_are_distinguished():
    report = generate_incident_report(
        verdict="suspicious", severity="low", iocs={}, mitre=None,
        recommendations=[], threat_intel=_ti_ok_and_error(),
    )
    # Successful lookup renders its real counts (0 here, but recorded),
    # with the IP defanged for presentation like the IOC section.
    assert "AbuseIPDB (45[.]77[.]65[.]211): confidence score 0, 0 reports" in report
    # Failed lookup is a failure, never a clean result.
    assert "AbuseIPDB (9[.]9[.]9[.]9): lookup failed - Threat-intel lookup timed out." in report
    # Successful VT check with no malicious findings.
    assert "VirusTotal (1[.]2[.]3[.]4): 0 malicious / 1 suspicious vendor flags" in report
    # Rationale counts failed lookups as missing, not clean.
    assert "1 failed" in report
    assert "their results are missing, not clean" in report


def test_unknown_ti_shape_is_not_presented_as_a_lookup():
    report = generate_incident_report(
        verdict="benign", severity="low", iocs={}, mitre=None,
        recommendations=[],
        threat_intel={"abuseipdb": [{"ip": "8.8.8.8"}], "virustotal": []},
    )
    assert "status unavailable - lookup state could not be determined" in report
    # The entry must not be rendered as if a lookup had produced numbers.
    assert "AbuseIPDB (8[.]8[.]8[.]8): confidence" not in report


def test_empty_ti_and_no_iocs_are_stated_honestly():
    report = generate_incident_report(
        verdict="inconclusive", severity="low",
        iocs={"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        mitre=None, recommendations=None, threat_intel=None,
    )
    assert "None identified" in report
    # The threat-intel block only renders when threat_intel is present; an
    # empty dict renders the explicit no-lookup line.
    report2 = generate_incident_report(
        verdict="inconclusive", severity="low", iocs={}, mitre=None,
        recommendations=[], threat_intel={"abuseipdb": [], "virustotal": []},
    )
    assert "No IPs were checked against threat-intel sources" in report2
