def generate_incident_report(
    verdict,
    severity,
    iocs,
    mitre,
    recommendations
):

    report = f"""
Incident Report

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

    report += "\nIndicators of Compromise:\n"

    if iocs.get("ips"):
        report += "\nIPs:\n"
        for ip in iocs["ips"]:
            report += f"- {ip}\n"

    if iocs.get("urls"):
        report += "\nURLs:\n"
        for url in iocs["urls"]:
            report += f"- {url}\n"

    if iocs.get("emails"):
        report += "\nEmails:\n"
        for email in iocs["emails"]:
            report += f"- {email}\n"

    report += "\nRecommendations:\n"

    for rec in recommendations:
        report += f"- {rec}\n"

    return report