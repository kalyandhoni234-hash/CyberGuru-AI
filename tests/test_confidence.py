from utils.confidence import compute_confidence


def _abuse(ip, score):
    return {"ip": ip, "result": {"data": {"abuseConfidenceScore": score, "totalReports": 10}}}


def _vt(ip, malicious=0, suspicious=0):
    return {
        "ip": ip,
        "result": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": 90,
                        "undetected": 10,
                    }
                }
            }
        },
    }


def test_thin_evidence_stays_low():
    # No lookups, no MITRE, no IOCs — confidence must be honestly low, not inflated.
    assert compute_confidence("likely_malicious", "critical") == 5


def test_single_weak_signal_is_low_confidence():
    # One AbuseIPDB hit at 30% (below the 40 moderate threshold): a weak signal
    # even though the verdict is "likely malicious" and severity is "high".
    ti = {"abuseipdb": [_abuse("1.2.3.4", 30)], "virustotal": []}
    conf = compute_confidence("likely_malicious", "high", threat_intel=ti)
    assert conf < 40


def test_multiple_corroborating_sources_is_high():
    ti = {
        "abuseipdb": [_abuse("45.77.65.211", 91)],
        "virustotal": [_vt("45.77.65.211", malicious=2)],
    }
    mitre = [{"id": "T1071", "name": "Application Layer Protocol"}]
    iocs = {"ips": ["45.77.65.211"], "domains": [], "urls": [], "hashes": [], "emails": []}
    conf = compute_confidence(
        "likely_malicious", "critical", threat_intel=ti, mitre_techniques=mitre, iocs=iocs
    )
    assert conf >= 80


def test_benign_with_clean_lookups_is_medium():
    ti = {
        "abuseipdb": [_abuse("8.8.8.8", 0)],
        "virustotal": [_vt("8.8.8.8", malicious=0, suspicious=0)],
    }
    conf = compute_confidence("benign", "low", threat_intel=ti)
    assert conf == 60


def test_benign_with_no_lookups_stays_low():
    assert compute_confidence("benign", "low") < 30


def test_confidence_is_independent_of_severity():
    ti = {
        "abuseipdb": [_abuse("45.77.65.211", 80)],
        "virustotal": [_vt("45.77.65.211", malicious=2)],
    }
    mitre = [{"id": "T1071", "name": "Application Layer Protocol"}]
    kwargs = dict(threat_intel=ti, mitre_techniques=mitre, iocs={"ips": ["45.77.65.211"]})
    assert compute_confidence("likely_malicious", "critical", **kwargs) == compute_confidence(
        "likely_malicious", "low", **kwargs
    )


def test_errors_in_threat_intel_are_ignored():
    ti = {
        "abuseipdb": [{"ip": "1.2.3.4", "error": "lookup failed"}],
        "virustotal": [{"ip": "1.2.3.4", "error": "lookup failed"}],
    }
    assert compute_confidence("suspicious", "medium", threat_intel=ti) < 30


def test_duplicate_lookups_do_not_double_count():
    one = {"abuseipdb": [_abuse("1.2.3.4", 91)], "virustotal": []}
    three = {
        "abuseipdb": [_abuse("1.2.3.4", 91), _abuse("1.2.3.4", 91), _abuse("1.2.3.4", 91)],
        "virustotal": [],
    }
    assert compute_confidence("suspicious", "high", threat_intel=one) == compute_confidence(
        "suspicious", "high", threat_intel=three
    )


def test_failed_lookup_is_not_a_clean_source():
    failed = {
        "abuseipdb": [{"ip": "8.8.8.8", "status": "error", "error": "timeout"}],
        "virustotal": [{"ip": "8.8.8.8", "status": "error", "error": "timeout"}],
    }
    # A benign verdict with two FAILED providers must not get clean-source credit.
    assert compute_confidence("benign", "low", threat_intel=failed) == 5


def test_benign_verdict_contradicted_by_provider_is_capped():
    ti = {
        "abuseipdb": [_abuse("45.77.65.211", 95)],
        "virustotal": [_vt("45.77.65.211", malicious=12)],
    }
    conf = compute_confidence("benign", "low", threat_intel=ti)
    assert conf <= 25


def test_inconclusive_assessment_stays_low_with_clean_lookups():
    ti = {
        "abuseipdb": [_abuse("8.8.8.8", 0)],
        "virustotal": [_vt("8.8.8.8", malicious=0, suspicious=0)],
    }
    assert compute_confidence("inconclusive", "low", threat_intel=ti) <= 40


def test_malformed_provider_values_are_ignored():
    ti = {
        "abuseipdb": [{"ip": "1.2.3.4", "result": {"data": {"abuseConfidenceScore": "NaN"}}}],
        "virustotal": [
            {"ip": "2.2.2.2", "result": {"data": {"attributes": {"last_analysis_stats": {"malicious": "lots"}}}}}
        ],
    }
    assert compute_confidence("benign", "low", threat_intel=ti) == 5


def test_value_is_clamped_to_0_100():
    ti = {
        "abuseipdb": [_abuse("a", 100), _abuse("b", 99)],
        "virustotal": [_vt("a", malicious=30), _vt("b", malicious=40)],
    }
    mitre = [{"id": "T1003", "name": "OS Credential Dumping"}] * 3
    iocs = {"ips": ["a", "b"], "hashes": ["aa" * 16], "urls": ["http://x.com"]}
    conf = compute_confidence(
        "likely_malicious", "critical", threat_intel=ti, mitre_techniques=mitre, iocs=iocs
    )
    assert 0 <= conf <= 100
