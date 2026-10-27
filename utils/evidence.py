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
    status = entry.get("status")
    if status == "not_applicable":
        return (
            f"AbuseIPDB {entry.get('ip')}: not applicable "
            f"({entry.get('reason') or 'Not Applicable'})"
        )
    if status == "not_found":
        return f"AbuseIPDB {entry.get('ip')}: no results found"
    if status == "error" or "error" in entry:
        return f"AbuseIPDB lookup failed for {entry.get('ip')}"
    data = (entry.get("result") or {}).get("data") or {}
    score = data.get("abuseConfidenceScore")
    reports = data.get("totalReports")
    if score is None:
        return f"AbuseIPDB {entry.get('ip')}: no abuse data returned"
    return f"AbuseIPDB {entry.get('ip')}: abuse confidence {score}%, {reports or 0} reports"


def _vt_detail(entry) -> str:
    status = entry.get("status")
    if status == "not_applicable":
        return (
            f"VirusTotal {entry.get('ip')}: not applicable "
            f"({entry.get('reason') or 'Not Applicable'})"
        )
    if status == "not_found":
        return f"VirusTotal {entry.get('ip')}: no results found"
    if status == "error" or "error" in entry:
        return f"VirusTotal lookup failed for {entry.get('ip')}"
    data = (entry.get("result") or {}).get("data") or {}
    stats = (data.get("attributes") or {}).get("last_analysis_stats") or {}
    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0
    return (
        f"VirusTotal {entry.get('ip')}: {malicious} malicious / "
        f"{suspicious} suspicious vendor flags"
    )


def _abuse_provenance(entry) -> tuple[bool, str]:
    """Return (verified, provenance) for an AbuseIPDB entry.

    Only a successful lookup with a numeric abuse-confidence score counts as
    externally verified. Errors, missing records, and skipped private ranges
    are explicitly unverified.
    """
    status = entry.get("status")
    if status == "not_applicable":
        return False, "provider-not-applicable"
    if status == "not_found":
        return False, "provider-not-found"
    if status == "error" or "error" in entry:
        return False, "provider-unavailable"
    data = (entry.get("result") or {}).get("data") or {}
    score = data.get("abuseConfidenceScore")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return False, "provider-malformed"
    if not 0 <= score <= 100:
        return False, "provider-malformed"
    return True, "provider"


def _vt_provenance(entry) -> tuple[bool, str]:
    """Return (verified, provenance) for a VirusTotal entry."""
    status = entry.get("status")
    if status == "not_applicable":
        return False, "provider-not-applicable"
    if status == "not_found":
        return False, "provider-not-found"
    if status == "error" or "error" in entry:
        return False, "provider-unavailable"
    data = (entry.get("result") or {}).get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return False, "provider-malformed"
    malicious = stats.get("malicious")
    if isinstance(malicious, bool) or not isinstance(malicious, (int, float)):
        return False, "provider-malformed"
    if malicious < 0:
        return False, "provider-malformed"
    return True, "provider"


def build_evidence(iocs=None, threat_intel=None, mitre_techniques=None) -> list:
    """Build the deterministic evidence registry.

    Each item has ``id``, ``type``, ``source``, ``detail``, ``verified`` and
    ``provenance``.  ``verified`` is True only for a successful external
    provider lookup with usable data.  MITRE mappings are heuristic and IOCs
    are extraction results, so both stay unverified; consumers must not
    present them as externally confirmed facts.

    IDs are assigned by deterministic ordering (AbuseIPDB, VirusTotal,
    MITRE, then IOCs), so the same investigation data always yields the
    same E-IDs.
    """
    evidence = []
    iocs = iocs if isinstance(iocs, dict) else {}
    threat_intel = threat_intel if isinstance(threat_intel, dict) else {}
    mitre_techniques = mitre_techniques if isinstance(mitre_techniques, list) else []

    def add(etype, source, detail, verified=False, provenance="derived"):
        evidence.append({
            "id": f"E-{len(evidence) + 1:02d}",
            "type": etype,
            "source": source,
            "detail": detail,
            "verified": bool(verified),
            "provenance": provenance,
        })

    for entry in threat_intel.get("abuseipdb") or []:
        verified, provenance = _abuse_provenance(entry)
        add("Threat Intel", "AbuseIPDB", _abuse_detail(entry), verified, provenance)
    for entry in threat_intel.get("virustotal") or []:
        verified, provenance = _vt_provenance(entry)
        add("Threat Intel", "VirusTotal", _vt_detail(entry), verified, provenance)
    for technique in mitre_techniques:
        if not isinstance(technique, dict):
            continue
        add(
            "MITRE",
            "MITRE ATT&CK",
            f"{technique.get('id', 'Unknown')} - {technique.get('name', 'Unknown')}",
            verified=False,
            provenance="heuristic",
        )
    for key in IOC_KEYS:
        label = IOC_LABELS[key]
        for value in iocs.get(key) or []:
            add("IOC", label, f"{label} {value}", verified=False, provenance="extraction")

    return evidence


def format_evidence_block(evidence: list) -> str:
    """Render the registry for injection into a model prompt.

    The verified/unverified marker is part of the prompt contract: a model
    must not describe an unverified extraction or heuristic mapping as an
    externally confirmed fact.
    """
    if not evidence:
        return (
            "EVIDENCE REGISTRY\n---------------\n"
            "No structured evidence available. Do not invent evidence IDs."
        )
    lines = [
        "EVIDENCE REGISTRY (cite these IDs; [unverified] is not external proof)",
        "---------------",
    ]
    for item in evidence:
        flag = "verified" if item.get("verified") else "unverified"
        lines.append(f"{item['id']} [{item['type']}] {item['detail']} [{flag}]")
    return "\n".join(lines)
