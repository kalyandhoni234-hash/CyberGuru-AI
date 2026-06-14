from utils.ioc_extractor import extract_iocs
from utils.mitre_mapper import lookup_mitre
from utils.abuseipdb_tool import check_abuseipdb
from utils.virustotal_tool import check_virustotal_ip
from utils.report_generator import generate_incident_report

from services.triage_service import analyze_artifact



def investigate(artifact_text):

    print("🔥 CYBERGURU AGENT EXECUTED 🔥")

    # Step 1: Extract IOCs
    iocs = extract_iocs(artifact_text)

    print("IOCs:", iocs)

    # Step 2: Threat Intel
    threat_intel = {
        "abuseipdb": [],
        "virustotal": []
    }

    for ip in iocs.get("ips", []):

        try:
            abuse_result = check_abuseipdb(ip)

            threat_intel["abuseipdb"].append({
                "ip": ip,
                "result": abuse_result
            })

        except Exception as e:

            threat_intel["abuseipdb"].append({
                "ip": ip,
                "error": str(e)
            })

        try:
            vt_result = check_virustotal_ip(ip)

            threat_intel["virustotal"].append({
                "ip": ip,
                "result": vt_result
            })

        except Exception as e:

            threat_intel["virustotal"].append({
                "ip": ip,
                "error": str(e)
            })

    print("Threat Intel:", threat_intel)

    # Step 3: Gemini Analysis
    analysis = analyze_artifact(artifact_text)

    print("Analysis:", analysis)

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

    print("MITRE:", mitre)

    # Step 5: Incident Report
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

    return {
        "analysis": analysis,
        "iocs": iocs,
        "threat_intel": threat_intel,
        "mitre": mitre,
        "report": report
    }