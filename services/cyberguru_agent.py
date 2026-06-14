from utils.ioc_extractor import extract_iocs
from utils.mitre_mapper import lookup_mitre
from utils.abuseipdb_tool import check_abuseipdb
from utils.virustotal_tool import check_virustotal_ip
from utils.report_generator import generate_incident_report

from services.triage_service import analyze_artifact


def investigate(artifact_text):

    # Step 1: Extract IOCs
    iocs = extract_iocs(artifact_text)

    # Step 2: Threat Intelligence Gathering
    threat_intel = {
        "abuseipdb": [],
        "virustotal": []
    }

    for ip in iocs["ips"]:

        # AbuseIPDB Lookup
        try:
            abuse_result = check_abuseipdb(ip)

            threat_intel["abuseipdb"].append(
                {
                    "ip": ip,
                    "result": abuse_result
                }
            )

        except Exception as e:

            threat_intel["abuseipdb"].append(
                {
                    "ip": ip,
                    "error": str(e)
                }
            )

        # VirusTotal Lookup
        try:
            vt_result = check_virustotal_ip(ip)

            threat_intel["virustotal"].append(
                {
                    "ip": ip,
                    "result": vt_result
                }
            )

        except Exception as e:

            threat_intel["virustotal"].append(
                {
                    "ip": ip,
                    "error": str(e)
                }
            )

    # Step 3: Gemini Analysis
    analysis = analyze_artifact(artifact_text)

    # Step 4: MITRE Mapping
    mitre = None

    analysis_text = analysis.get(
        "analysis",
        ""
    ).lower()

    if "brute force" in analysis_text:
        mitre = lookup_mitre("brute force")

    elif "phishing" in analysis_text:
        mitre = lookup_mitre("phishing")

    elif "powershell" in analysis_text:
        mitre = lookup_mitre("powershell")

    # Step 5: Generate Incident Report
    report = generate_incident_report(
        verdict=analysis.get("verdict"),
        severity=analysis.get("severity"),
        iocs=iocs,
        mitre=mitre,
        recommendations=[
            "Review affected systems",
            "Investigate related events",
            "Block malicious indicators if confirmed"
        ]
    )

    # Step 6: Return Full Investigation
    return {
        "analysis": analysis,
        "iocs": iocs,
        "threat_intel": threat_intel,
        "mitre": mitre,
        "report": report
    }