"""Tests for evidence-specific recommendation generation."""

from utils.recommendations import build_specific_recommendations


class TestVerdictDriven:
    def test_likely_malicious_escalates(self):
        recs = build_specific_recommendations(verdict="likely_malicious")
        assert any("Escalate to incident response" in r for r in recs)

    def test_benign_advises_closeout(self):
        recs = build_specific_recommendations(verdict="benign")
        assert any("No malicious indicators confirmed" in r for r in recs)

    def test_high_severity_prioritises(self):
        recs = build_specific_recommendations(verdict="likely_malicious", severity="high")
        assert any("high-priority" in r for r in recs)

    def test_low_confidence_asks_for_corroboration(self):
        recs = build_specific_recommendations(verdict="suspicious", confidence=30)
        assert any("gather corroborating telemetry" in r for r in recs)


class TestThreatIntelDriven:
    def test_high_abuse_score_recommends_block(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            threat_intel={
                "abuseipdb": [{"ip": "45.77.65.211", "result": {"data": {"abuseConfidenceScore": 91, "totalReports": 12}}}]
            },
        )
        assert any("Block 45.77.65.211" in r and "91%" in r for r in recs)

    def test_mid_abuse_score_recommends_investigation(self):
        recs = build_specific_recommendations(
            verdict="suspicious",
            threat_intel={
                "abuseipdb": [{"ip": "1.2.3.4", "result": {"data": {"abuseConfidenceScore": 55}}}]
            },
        )
        assert any("Investigate traffic to/from 1.2.3.4" in r for r in recs)

    def test_vt_malicious_recommends_quarantine(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            threat_intel={
                "virustotal": [{"ip": "2.2.2.2", "result": {"data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}}}]
            },
        )
        assert any("Treat 2.2.2.2 as hostile" in r and "4 malicious" in r for r in recs)

    def test_error_entries_are_skipped(self):
        recs = build_specific_recommendations(
            verdict="benign",
            threat_intel={
                "abuseipdb": [{"ip": "1.1.1.1", "error": "boom"}],
                "virustotal": [{"ip": "2.2.2.2", "error": "boom"}],
            },
        )
        assert not any("Block " in r or "hostile" in r for r in recs)


class TestIocDriven:
    def test_domains_urls_hashes_emails(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            iocs={
                "domains": ["evil.example"],
                "urls": ["http://evil.example/p"],
                "hashes": ["abc123"],
                "emails": ["phish@evil.example"],
            },
        )
        joined = "\n".join(recs)
        assert "DNS sinkhole" in joined
        assert "web proxy" in joined
        assert "EDR hash search" in joined
        assert "quarantine them" in joined


class TestMitreDriven:
    def test_known_technique_maps_to_action(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}],
        )
        assert any("account lockout" in r for r in recs)

    def test_unknown_technique_asks_to_hunt(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            mitre_techniques=[{"id": "T9999", "name": "Weird"}],
        )
        assert any("T9999" in r and "Hunt" in r for r in recs)


class TestDedup:
    def test_no_duplicate_recommendations(self):
        recs = build_specific_recommendations(
            verdict="likely_malicious",
            severity="high",
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}] * 3,
        )
        assert len(recs) == len(set(recs))
