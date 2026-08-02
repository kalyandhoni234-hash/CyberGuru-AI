"""
Specific, evidence-grounded recommendations.

Builds deterministic next steps from the investigation's structured data
(threat-intel lookups, extracted IOCs, MITRE technique, verdict/severity)
rather than generic boilerplate. These complement the AI narrative's next
steps and are surfaced both in the incident report and the dashboard.

Each recommendation cites the concrete value it refers to (IP, domain,
hash, technique id) so an analyst can act on it directly.
"""


def _abuse_recs(threat_intel) -> list:
    recs = []
    for entry in threat_intel.get("abuseipdb") or []:
        if "error" in entry:
            continue
        data = (entry.get("result") or {}).get("data") or {}
        score = data.get("abuseConfidenceScore") or 0
        ip = entry.get("ip")
        if score >= 75:
            recs.append(
                f"Block {ip} at the perimeter and revoke any sessions from it "
                f"(AbuseIPDB confidence {score}%)."
            )
        elif score >= 40:
            recs.append(
                f"Investigate traffic to/from {ip} before blocking "
                f"(AbuseIPDB confidence {score}%)."
            )
    return recs


def _vt_recs(threat_intel) -> list:
    recs = []
    for entry in threat_intel.get("virustotal") or []:
        if "error" in entry:
            continue
        data = (entry.get("result") or {}).get("data") or {}
        stats = (data.get("attributes") or {}).get("last_analysis_stats") or {}
        malicious = stats.get("malicious") or 0
        ip = entry.get("ip")
        if malicious > 0:
            recs.append(
                f"Treat {ip} as hostile and quarantine traffic to it "
                f"(VirusTotal: {malicious} malicious vendor flags)."
            )
    return recs


def _ioc_recs(iocs) -> list:
    iocs = iocs or {}
    recs = []
    for domain in iocs.get("domains") or []:
        recs.append(f"Block {domain} via DNS sinkhole and deny-list it on the mail gateway.")
    for url in iocs.get("urls") or []:
        recs.append(f"Block {url} at the web proxy and email gateway, then scan the sender's domain.")
    for h in iocs.get("hashes") or []:
        recs.append(f"Hunt for the file hash {h} across endpoints with EDR hash search.")
    for email in iocs.get("emails") or []:
        recs.append(f"Search mail logs for inbound messages from {email} and quarantine them.")
    return recs


_MITRE_RECS = {
    "t1110": "Enforce account lockout and MFA; review successful logons following the brute-force bursts.",
    "t1566": "Audit mail-gateway rules, check for newly created mailbox rules, and validate the reporting user's account.",
    "t1059": "Audit command/script execution logs and enable script-block logging on affected hosts.",
    "t1053": "Review scheduled tasks and services for persistence added around the event time.",
    "t1547": "Review autoruns, startup keys and services for persistence mechanisms.",
    "t1071": "Inspect outbound traffic to the C2 endpoint and look for beaconing patterns.",
    "t1027": "Decode/defang embedded payloads and scan the artifact with static analysis before opening.",
    "t1562": "Check whether security tooling or logging was tampered with on affected hosts.",
    "t1078": "Rotate credentials for the compromised account and review recent activity under it.",
    "t1134": "Audit privilege-escalation events and revalidate the account's group memberships.",
}


def _mitre_recs(mitre_techniques) -> list:
    recs = []
    for technique in mitre_techniques:
        tid = (technique.get("id") or "").lower()
        name = technique.get("name") or "unknown"
        if tid in _MITRE_RECS:
            recs.append(_MITRE_RECS[tid])
        else:
            recs.append(
                f"Hunt across the environment for other activity matching "
                f"{tid.upper() or name} - {name}."
            )
    return recs


def build_specific_recommendations(
    iocs=None, threat_intel=None, mitre_techniques=None, verdict=None, severity=None, confidence=None
) -> list:
    """Ordered, deduplicated, evidence-specific next steps."""
    verdict = verdict or "inconclusive"
    severity = severity or "low"
    threat_intel = threat_intel or {}
    mitre_techniques = mitre_techniques or []

    recs = []

    if verdict == "likely_malicious":
        recs.append("Escalate to incident response and contain affected hosts immediately.")
    elif verdict == "suspicious":
        recs.append("Correlate with surrounding log activity before taking blocking actions.")
    elif verdict == "benign":
        recs.append("No malicious indicators confirmed — close out if consistent with the environment.")
    else:
        recs.append("Re-run with additional context or request analyst review before acting.")

    if severity in ("critical", "high"):
        recs.append("Treat as a high-priority case — contain, preserve logs, and notify the IR team.")

    if confidence is not None and confidence < 40:
        recs.append("Confidence is low — gather corroborating telemetry before actioning indicators.")

    recs += _abuse_recs(threat_intel)
    recs += _vt_recs(threat_intel)
    recs += _ioc_recs(iocs)
    recs += _mitre_recs(mitre_techniques)

    seen, ordered = set(), []
    for rec in recs:
        if rec not in seen:
            seen.add(rec)
            ordered.append(rec)
    return ordered
