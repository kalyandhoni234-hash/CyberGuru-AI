"""
Evidence registry for traceable AI citations.

Every piece of structured evidence an AI claim can rest on gets a stable
E-0N id: threat-intel lookups (AbuseIPDB, VirusTotal), MITRE ATT&CK
matches, and extracted IOCs. The copilot prompt lists these IDs and asks
the model to cite them; the UI renders the same registry as a legend so
a claim like "flagged by E-01" is traceable to the exact source and value.

The registry is built deterministically from the investigation data, so
the IDs are stable across requests for the same investigation. Ordering
is fixed: threat-intel first (AbuseIPDB then VirusTotal), then MITRE,
then IOCs.

Note on the main analysis narrative: the triage agent runs before this
registry can exist (the evidence is produced by the model's own tool
calls), so the narrative is prompted to cite source + value + metric
(e.g. "AbuseIPDB reports 91% confidence for 45.77.65.211") which maps
one-to-one onto a legend entry. The copilot, which runs post-hoc against
a completed investigation, cites the E-IDs directly.
"""

IOC_KEYS = ("ips", "domains", "urls", "hashes", "emails")
IOC_LABELS = {
    "ips": "IP",
    "domains": "Domain",
    "urls": "URL",
    "hashes": "Hash",
    "emails": "Email",
}


def _abuse_detail(entry) -> str:
    if "error" in entry:
        return f"AbuseIPDB lookup failed for {entry.get('ip')}"
    data = (entry.get("result") or {}).get("data") or {}
    score = data.get("abuseConfidenceScore")
    reports = data.get("totalReports")
    if score is None:
        return f"AbuseIPDB {entry.get('ip')}: no abuse data returned"
    return f"AbuseIPDB {entry.get('ip')}: abuse confidence {score}%, {reports or 0} reports"


def _vt_detail(entry) -> str:
    if "error" in entry:
        return f"VirusTotal lookup failed for {entry.get('ip')}"
    data = (entry.get("result") or {}).get("data") or {}
    stats = (data.get("attributes") or {}).get("last_analysis_stats") or {}
    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0
    return (
        f"VirusTotal {entry.get('ip')}: {malicious} malicious / "
        f"{suspicious} suspicious vendor flags"
    )


def build_evidence(iocs=None, threat_intel=None, mitre_techniques=None) -> list:
    """Build the deterministic evidence registry as a list of
    {"id", "type", "source", "detail"} dicts, ordered E-01, E-02, ..."""
    evidence = []
    iocs = iocs or {}
    threat_intel = threat_intel or {}
    mitre_techniques = mitre_techniques or []

    def add(etype, source, detail):
        evidence.append({
            "id": f"E-{len(evidence) + 1:02d}",
            "type": etype,
            "source": source,
            "detail": detail,
        })

    for entry in threat_intel.get("abuseipdb") or []:
        add("Threat Intel", "AbuseIPDB", _abuse_detail(entry))
    for entry in threat_intel.get("virustotal") or []:
        add("Threat Intel", "VirusTotal", _vt_detail(entry))
    for technique in mitre_techniques:
        add(
            "MITRE",
            "MITRE ATT&CK",
            f"{technique.get('id', 'Unknown')} - {technique.get('name', 'Unknown')}",
        )
    for key in IOC_KEYS:
        label = IOC_LABELS[key]
        for value in iocs.get(key) or []:
            add("IOC", label, f"{label} {value}")

    return evidence


def format_evidence_block(evidence: list) -> str:
    """Render the registry for injection into a model prompt."""
    if not evidence:
        return "EVIDENCE REGISTRY\n---------------\nNo structured evidence available."
    lines = ["EVIDENCE REGISTRY (cite these IDs in your answer)", "---------------"]
    for item in evidence:
        lines.append(f"{item['id']} [{item['type']}] {item['detail']}")
    return "\n".join(lines)
