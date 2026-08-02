"""
Deterministic, evidence-based confidence scoring (0-100).

Confidence reflects the STRENGTH and corroboration of the evidence behind
an assessment. It is deliberately kept independent of severity:

    severity   = how bad the finding is if it is real
    confidence = how sure we are that the assessment is correct

The score is derived entirely from structured pipeline data (threat-intel
results, MITRE ATT&CK mappings, extracted IOCs) so it is explainable,
consistent across runs, and unit-testable. The AI never asserts a
confidence number in prose.

Scoring model (documented thresholds):
  * AbuseIPDB confidence score >= 75  -> +45 (strong single source)
  * AbuseIPDB confidence score >= 40  -> +30 (moderate)
  * AbuseIPDB confidence score  >  0  -> +12 (weak signal)
  * VirusTotal malicious flags >= 10  -> +45 (strong)
  * VirusTotal malicious flags >=  3  -> +35 (moderate)
  * VirusTotal malicious flags  >  0  -> +25 (weak)
  * VirusTotal suspicious flags only  -> +10
  * Additional VirusTotal IPs looked up (multiple IOCs corroborated) -> +5
  * MITRE ATT&CK technique matched    -> +15 (behavioral corroboration)
  * Any IOC extracted                 -> +5  (weakest: evidence exists)
  * Multi-source agreement: 2 sources -> +5, 3+ sources -> +10

For clean (benign) assessments, threat-intel lookups that returned no
malicious indicators corroborate the clean verdict (+30 per clean
source, capped at 60). With no lookups and no MITRE match the confidence
stays honestly low (thin evidence), never inflated.

Everything is clamped to 0-100. A result with no corroborating evidence
at all floors at 5 rather than 0.
"""

IOC_KEYS = ("ips", "domains", "urls", "hashes", "emails")


def _ioc_count(iocs) -> int:
    if not iocs:
        return 0
    return sum(len(iocs.get(key) or []) for key in IOC_KEYS)


def compute_confidence(
    verdict,
    severity=None,
    threat_intel=None,
    mitre_techniques=None,
    iocs=None,
) -> int:
    """
    Return a deterministic 0-100 confidence score for an assessment.

    Args:
        verdict:        "likely_malicious" | "suspicious" | "inconclusive" | "benign"
        severity:       Unused in the score (kept in the signature so the
                        caller passes it explicitly and the independence of
                        confidence from severity is visible). May be None.
        threat_intel:   {"abuseipdb": [...], "virustotal": [...]} as produced
                        by services.cyberguru_agent (each entry has "ip" and
                        either "result" or "error").
        mitre_techniques: list of {"id", "name"} dicts.
        iocs:           {"ips": [...], "domains": [...], ...} as produced by
                        utils.ioc_extractor.
    """
    threat_intel = threat_intel or {}
    mitre_techniques = mitre_techniques or []
    iocs = iocs or {}

    abuse_entries = threat_intel.get("abuseipdb") or []
    vt_entries = threat_intel.get("virustotal") or []

    verdict = (verdict or "inconclusive").lower()

    malicious_signals = 0
    clean_sources = 0
    corroborating_sources = 0

    # ── AbuseIPDB ──
    max_abuse = 0
    abuse_queried = False
    for entry in abuse_entries:
        if "error" in entry:
            continue
        data = (entry.get("result") or {}).get("data")
        if data is None:
            continue
        abuse_queried = True
        try:
            max_abuse = max(max_abuse, int(data.get("abuseConfidenceScore") or 0))
        except (TypeError, ValueError):
            continue

    if max_abuse >= 75:
        malicious_signals += 45
        corroborating_sources += 1
    elif max_abuse >= 40:
        malicious_signals += 30
        corroborating_sources += 1
    elif max_abuse > 0:
        malicious_signals += 12
    elif abuse_queried:
        clean_sources += 1

    # ── VirusTotal ──
    vt_total_malicious = 0
    vt_total_suspicious = 0
    vt_lookup_count = 0
    for entry in vt_entries:
        if "error" in entry:
            continue
        data = (entry.get("result") or {}).get("data")
        if data is None:
            continue
        stats = (data.get("attributes") or {}).get("last_analysis_stats") or {}
        vt_lookup_count += 1
        try:
            vt_total_malicious += int(stats.get("malicious") or 0)
            vt_total_suspicious += int(stats.get("suspicious") or 0)
        except (TypeError, ValueError):
            continue

    if vt_total_malicious >= 10:
        malicious_signals += 45
        corroborating_sources += 1
    elif vt_total_malicious >= 3:
        malicious_signals += 35
        corroborating_sources += 1
    elif vt_total_malicious > 0:
        malicious_signals += 25
    elif vt_lookup_count > 0:
        clean_sources += 1
    if vt_lookup_count > 1:
        malicious_signals += 5

    # ── MITRE ATT&CK corroboration ──
    if mitre_techniques:
        malicious_signals += 15
        corroborating_sources += 1

    # ── IOCs: weakest corroboration (evidence exists at all) ──
    if _ioc_count(iocs) > 0:
        malicious_signals += 5

    if verdict in ("likely_malicious", "suspicious"):
        base = malicious_signals
    else:
        # benign / inconclusive: only clean lookups corroborate; otherwise the
        # evidence is thin and confidence must stay honestly low.
        base = min(60, clean_sources * 30)

    if corroborating_sources >= 3:
        base = min(100, base + 10)
    elif corroborating_sources >= 2:
        base = min(100, base + 5)

    return max(5, min(100, base))
