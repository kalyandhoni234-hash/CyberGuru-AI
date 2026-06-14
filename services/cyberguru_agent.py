import hashlib

from utils.ioc_extractor import extract_iocs
from utils.report_generator import generate_incident_report
from services.db_service import save_investigation, find_recent_investigation

from services.triage_service import analyze_artifact


# How long a cached investigation result is considered "fresh" enough
# to skip re-running the full pipeline for an identical artifact.
DEDUPE_WINDOW_HOURS = 24


def _hash_artifact(artifact_text):
    return hashlib.sha256(artifact_text.strip().encode("utf-8")).hexdigest()


def investigate(artifact_text, user_id=None, allow_cached=True):

    artifact_hash = _hash_artifact(artifact_text)

    if allow_cached:
        cached = find_recent_investigation(artifact_hash, max_age_hours=DEDUPE_WINDOW_HOURS)
        if cached:
            return _result_from_db_row(cached, from_cache=True)

    # Step 1: Extract IOCs (used for the report and for de-duplication;
    # the triage agent also sees the raw artifact and may look these up
    # itself via tool calls)
    iocs = extract_iocs(artifact_text)

    # Step 2: Gemini Triage Agent (decides its own threat-intel + MITRE lookups)
    analysis = analyze_artifact(artifact_text)

    analysis_error = None
    if analysis.get("status") == "error":
        analysis_error = analysis.get("error", "Unknown error")

    # Step 3: Collect threat-intel results from whatever tool calls the
    # agent made, so the report can show them
    threat_intel = {"abuseipdb": [], "virustotal": []}

    for call in analysis.get("tool_calls", []):
        ip = call.get("args", {}).get("ip")
        result = call.get("result", {})

        if call["name"] == "check_abuseipdb":
            entry = {"ip": ip}
            if "error" in result:
                entry["error"] = result["error"]
            else:
                entry["result"] = result
            threat_intel["abuseipdb"].append(entry)

        elif call["name"] == "check_virustotal_ip":
            entry = {"ip": ip}
            if "error" in result:
                entry["error"] = result["error"]
            else:
                entry["result"] = result
            threat_intel["virustotal"].append(entry)

    # Step 4: MITRE - take the first technique the agent identified, if any
    mitre_techniques = analysis.get("mitre_techniques", [])
    mitre = mitre_techniques[0] if mitre_techniques else None

    verdict = analysis.get("verdict")
    severity = analysis.get("severity")

    # Step 5: Incident Report
    report = generate_incident_report(
        verdict=verdict,
        severity=severity,
        iocs=iocs,
        mitre=mitre,
        threat_intel=threat_intel,
        analysis_error=analysis_error,
        recommendations=[
            "Review affected systems",
            "Investigate related events",
            "Block malicious indicators if confirmed"
        ]
    )

    # Step 6: Persist
    if user_id is not None:
        save_investigation(
            user_id=user_id,
            artifact_hash=artifact_hash,
            artifact_text=artifact_text,
            verdict=verdict,
            severity=severity,
            mitre=mitre,
            iocs=iocs,
            threat_intel=threat_intel,
            report=report,
            analysis_error=analysis_error
        )

    return {
        "analysis": analysis,
        "iocs": iocs,
        "threat_intel": threat_intel,
        "mitre": mitre,
        "mitre_techniques": mitre_techniques,
        "report": report,
        "from_cache": False,
    }


def _result_from_db_row(row, from_cache=False):
    """Reconstruct an investigate() result dict from a saved DB row."""
    mitre = None
    if row.get("mitre_id"):
        mitre = {"id": row["mitre_id"], "name": row.get("mitre_name")}

    return {
        "analysis": {
            "verdict": row.get("verdict"),
            "severity": row.get("severity"),
            "status": "error" if row.get("analysis_error") else "completed",
            "error": row.get("analysis_error"),
        },
        "iocs": row.get("iocs") or {},
        "threat_intel": row.get("threat_intel") or {},
        "mitre": mitre,
        "mitre_techniques": [mitre] if mitre else [],
        "report": row.get("report", ""),
        "from_cache": from_cache,
    }
