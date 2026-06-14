from utils.defang import defang_iocs


def generate_incident_report(
    verdict,
    severity,
    iocs,
    mitre,
    recommendations,
    threat_intel=None,
    analysis_error=None
):

    verdict = verdict or "unknown"
    severity = severity or "unknown"

    safe_iocs = defang_iocs(iocs)

    report = "Incident Report\n"

    if analysis_error:
        report += f"""
WARNING: AI analysis failed - this report is based on IOC extraction and
threat intel only. Verdict/severity below are placeholders.
Error: {analysis_error}
"""

    report += f"""
Verdict:
{verdict}

Severity:
{severity}
"""

    if mitre:
        report += f"""

MITRE ATT&CK:
{mitre.get('id', 'N/A')} - {mitre.get('name', 'N/A')}
"""

    report += "\nIndicators of Compromise (defanged):\n"

    has_iocs = False

    if safe_iocs.get("ips"):
        has_iocs = True
        report += "\nIPs:\n"
        for ip in safe_iocs["ips"]:
            report += f"- {ip}\n"

    if safe_iocs.get("urls"):
        has_iocs = True
        report += "\nURLs:\n"
        for url in safe_iocs["urls"]:
            report += f"- {url}\n"

    if safe_iocs.get("emails"):
        has_iocs = True
        report += "\nEmails:\n"
        for email in safe_iocs["emails"]:
            report += f"- {email}\n"

    if not has_iocs:
        report += "- None identified\n"

    if threat_intel:
        report += "\nThreat Intelligence:\n"

        abuse_entries = threat_intel.get("abuseipdb", [])
        vt_entries = threat_intel.get("virustotal", [])

        if not abuse_entries and not vt_entries:
            report += "- No IPs were checked against threat-intel sources\n"

        for entry in abuse_entries:
            ip = entry.get("ip")
            if "error" in entry:
                report += f"- AbuseIPDB ({ip}): lookup failed - {entry['error']}\n"
            else:
                data = entry.get("result", {}).get("data", {})
                score = data.get("abuseConfidenceScore", "N/A")
                reports = data.get("totalReports", "N/A")
                report += (
                    f"- AbuseIPDB ({ip}): confidence score {score}, "
                    f"{reports} reports\n"
                )

        for entry in vt_entries:
            ip = entry.get("ip")
            if "error" in entry:
                report += f"- VirusTotal ({ip}): lookup failed - {entry['error']}\n"
            else:
                data = entry.get("result", {}).get("data", {})
                stats = data.get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", "N/A")
                suspicious = stats.get("suspicious", "N/A")
                report += (
                    f"- VirusTotal ({ip}): {malicious} malicious / "
                    f"{suspicious} suspicious vendor flags\n"
                )

    report += "\nRecommendations:\n"

    if recommendations:
        for rec in recommendations:
            report += f"- {rec}\n"
    else:
        report += "- None\n"

    return report