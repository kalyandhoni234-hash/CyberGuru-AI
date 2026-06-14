import re

# Expanded MITRE ATT&CK technique map, covering the techniques most
# relevant to log/email/malware triage. Not exhaustive (full ATT&CK has
# 600+ techniques/sub-techniques) but covers common findings.
MITRE_MAP = {
    "brute force": {"id": "T1110", "name": "Brute Force"},
    "phishing": {"id": "T1566", "name": "Phishing"},
    "spearphishing": {"id": "T1566.001", "name": "Spearphishing Attachment"},
    "spearphishing link": {"id": "T1566.002", "name": "Spearphishing Link"},
    "powershell": {"id": "T1059.001", "name": "PowerShell"},
    "command and scripting interpreter": {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "dns tunneling": {"id": "T1071.004", "name": "DNS Tunneling"},
    "application layer protocol": {"id": "T1071", "name": "Application Layer Protocol"},
    "valid accounts": {"id": "T1078", "name": "Valid Accounts"},
    "credential dumping": {"id": "T1003", "name": "OS Credential Dumping"},
    "lateral movement": {"id": "T1021", "name": "Remote Services"},
    "remote desktop protocol": {"id": "T1021.001", "name": "Remote Desktop Protocol"},
    "lolbin": {"id": "T1218", "name": "System Binary Proxy Execution"},
    "lolbins": {"id": "T1218", "name": "System Binary Proxy Execution"},
    "scheduled task": {"id": "T1053", "name": "Scheduled Task/Job"},
    "registry": {"id": "T1112", "name": "Modify Registry"},
    "persistence": {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
    "service creation": {"id": "T1543.003", "name": "Windows Service"},
    "process injection": {"id": "T1055", "name": "Process Injection"},
    "exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
    "beaconing": {"id": "T1071", "name": "Application Layer Protocol (C2 Beaconing)"},
    "command and control": {"id": "T1071", "name": "Application Layer Protocol"},
    "encoded payload": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "obfuscation": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "privilege escalation": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact"},
    "data encryption": {"id": "T1486", "name": "Data Encrypted for Impact"},
    "discovery": {"id": "T1082", "name": "System Information Discovery"},
    "network scanning": {"id": "T1046", "name": "Network Service Discovery"},
    "sql injection": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "exploit public-facing application": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "credential prompt": {"id": "T1056.001", "name": "Keylogging"},
    "drive-by compromise": {"id": "T1189", "name": "Drive-by Compromise"},
    "supply chain compromise": {"id": "T1195", "name": "Supply Chain Compromise"},
    "impersonation": {"id": "T1656", "name": "Impersonation"},
}

# Pattern to find an explicit MITRE technique ID anywhere in text,
# e.g. "T1110", "T1566.001"
_TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Reverse map from technique ID -> name, built from MITRE_MAP, for when
# we only get an ID and need a friendly name.
_ID_TO_NAME = {v["id"].upper(): v["name"] for v in MITRE_MAP.values()}


def lookup_mitre(technique):
    """Look up a technique by free-text name."""
    return MITRE_MAP.get(
        technique.lower(),
        {"id": "Unknown", "name": technique}
    )


def extract_mitre_techniques(analysis_text, max_results=3):
    """
    Extract one or more MITRE techniques from an analysis text.

    Strategy:
      1. Look for explicit technique IDs (e.g. "T1110") - these are the
         most reliable signal, especially if the LLM was prompted to
         include them.
      2. Fall back to keyword matching against MITRE_MAP for techniques
         mentioned by name without an ID.

    Returns a list of {"id": ..., "name": ...} dicts, deduplicated,
    in order of first appearance. Empty list if nothing found.
    """
    if not analysis_text:
        return []

    results = []
    seen_ids = set()

    # Pass 1: explicit technique IDs
    for match in _TECHNIQUE_ID_PATTERN.finditer(analysis_text):
        tech_id = match.group(0).upper()
        if tech_id in seen_ids:
            continue
        seen_ids.add(tech_id)
        name = _ID_TO_NAME.get(tech_id, "Unknown Technique")
        results.append({"id": tech_id, "name": name})
        if len(results) >= max_results:
            return results

    # Pass 2: keyword matching by technique name
    text_lower = analysis_text.lower()
    for keyword, info in MITRE_MAP.items():
        if info["id"].upper() in seen_ids:
            continue
        if keyword in text_lower:
            seen_ids.add(info["id"].upper())
            results.append(info)
            if len(results) >= max_results:
                break

    return results