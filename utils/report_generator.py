def generate_incident_report(
    verdict,
    severity,
    iocs,
    mitre,
    recommendations
):

    report = f"""
# Incident Report

Verdict:
{verdict}

Severity:
{severity}

MITRE ATT&CK:
{mitre}

IOCs:
{iocs}

Recommendations:
{recommendations}
"""

    return report