"""Tests for the evidence registry used for traceable AI citations."""

from utils.evidence import build_evidence, format_evidence_block, IOC_KEYS


class TestBuildEvidenceOrdering:
    def test_empty_inputs_produce_empty_registry(self):
        assert build_evidence() == []

    def test_order_is_abuseipdb_then_virustotal(self):
        evidence = build_evidence(
            threat_intel={
                "abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {"abuseConfidenceScore": 90, "totalReports": 4}}}],
                "virustotal": [{"ip": "2.2.2.2", "result": {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}}]},
        )
        assert [e["source"] for e in evidence] == ["AbuseIPDB", "VirusTotal"]

    def test_mitre_entries_follow_threat_intel(self):
        evidence = build_evidence(
            threat_intel={"abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {}}}]},
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}],
        )
        assert evidence[1]["source"] == "MITRE ATT&CK"
        assert evidence[1]["detail"] == "T1110 - Brute Force"

    def test_iocs_last_and_grouped_by_type(self):
        evidence = build_evidence(
            iocs={"ips": ["1.1.1.1"], "domains": ["evil.example"]},
        )
        assert [e["source"] for e in evidence] == ["IP", "Domain"]

    def test_ioc_keys_iterate_all_five_types(self):
        assert tuple(IOC_KEYS) == ("ips", "domains", "urls", "hashes", "emails")

    def test_domain_ioc_uses_ip_keys_skip(self):
        evidence = build_evidence(iocs={"domains": ["a.example"], "hashes": ["abc123"]})
        assert [e["type"] for e in evidence] == ["IOC", "IOC"]
        assert "Domain a.example" in evidence[0]["detail"]
        assert "Hash abc123" in evidence[1]["detail"]


class TestEvidenceIds:
    def test_ids_are_sequential_and_zero_padded(self):
        evidence = build_evidence(
            threat_intel={
                "abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {}}}],
                "virustotal": [{"ip": "2.2.2.2", "result": {"data": {}}}],
            },
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}],
            iocs={"ips": ["3.3.3.3"]},
        )
        assert [e["id"] for e in evidence] == ["E-01", "E-02", "E-03", "E-04"]

    def test_ids_are_stable_for_same_input(self):
        data = {"threat_intel": {"abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {}}}]}}
        first = build_evidence(**data)
        second = build_evidence(**data)
        assert [e["id"] for e in first] == [e["id"] for e in second]


class TestEvidenceDetails:
    def test_abuse_detail_includes_score_and_reports(self):
        evidence = build_evidence(
            threat_intel={"abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {"abuseConfidenceScore": 91, "totalReports": 12}}}]},
        )
        assert evidence[0]["detail"] == "AbuseIPDB 1.1.1.1: abuse confidence 91%, 12 reports"

    def test_abuse_error_entry_flagged(self):
        evidence = build_evidence(threat_intel={"abuseipdb": [{"ip": "1.1.1.1", "error": "boom"}]})
        assert "lookup failed" in evidence[0]["detail"]

    def test_vt_detail_includes_vendor_flags(self):
        evidence = build_evidence(
            threat_intel={"virustotal": [{"ip": "2.2.2.2", "result": {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}} ]},
        )
        assert evidence[0]["detail"] == "VirusTotal 2.2.2.2: 3 malicious / 1 suspicious vendor flags"

    def test_abuse_not_applicable_entry_mentions_reason(self):
        evidence = build_evidence(
            threat_intel={"abuseipdb": [{"ip": "203.0.113.77", "status": "not_applicable", "reason": "Reserved/Documentation Range (RFC 5737 TEST-NET)"}]},
        )
        assert "not applicable" in evidence[0]["detail"]
        assert "RFC 5737 TEST-NET" in evidence[0]["detail"]

    def test_vt_not_found_entry_flagged(self):
        evidence = build_evidence(
            threat_intel={"virustotal": [{"ip": "8.8.8.8", "status": "not_found"}]},
        )
        assert "no results found" in evidence[0]["detail"]


class TestProvenance:
    def test_successful_provider_lookup_is_verified(self):
        evidence = build_evidence(
            threat_intel={
                "abuseipdb": [
                    {"ip": "1.1.1.1", "status": "ok", "result": {"data": {"abuseConfidenceScore": 0}}}
                ]
            }
        )
        assert evidence[0]["verified"] is True
        assert evidence[0]["provenance"] == "provider"

    def test_failed_lookup_is_not_verified(self):
        evidence = build_evidence(
            threat_intel={
                "abuseipdb": [
                    {"ip": "1.1.1.1", "status": "error", "error": "timeout"}
                ]
            }
        )
        assert evidence[0]["verified"] is False
        assert evidence[0]["provenance"] == "provider-unavailable"

    def test_malformed_provider_payload_is_not_verified(self):
        evidence = build_evidence(
            threat_intel={
                "virustotal": [
                    {"ip": "1.1.1.1", "status": "ok", "result": {"data": {"attributes": {}}}}
                ]
            }
        )
        assert evidence[0]["verified"] is False
        assert evidence[0]["provenance"] == "provider-malformed"

    def test_mitre_and_iocs_are_labelled_unverified(self):
        evidence = build_evidence(
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}],
            iocs={"ips": ["1.1.1.1"]},
        )
        assert all(item["verified"] is False for item in evidence)
        assert [item["provenance"] for item in evidence] == ["heuristic", "extraction"]


class TestFormatEvidenceBlock:
    def test_empty_registry_renders_placeholder(self):
        out = format_evidence_block([])
        assert "No structured evidence available." in out

    def test_renders_ids_and_details(self):
        evidence = build_evidence(
            threat_intel={"abuseipdb": [{"ip": "1.1.1.1", "result": {"data": {"abuseConfidenceScore": 80, "totalReports": 2}}}]},
        )
        out = format_evidence_block(evidence)
        assert "EVIDENCE REGISTRY" in out
        assert "E-01 [Threat Intel] AbuseIPDB 1.1.1.1: abuse confidence 80%, 2 reports" in out
