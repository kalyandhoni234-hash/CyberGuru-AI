"""
Cybersecurity Triage Service
Handles security artifact analysis using Gemini Managed Agents
"""
import os





from google import genai


# Initialize Gemini client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
print("Script started")

api_key = os.getenv("GEMINI_API_KEY")
print("API Key found:", api_key is not None)
print("Client created successfully")
SYSTEM_PROMPT = """# Cybersecurity Triage Agent

You analyze security-related artifacts: log files, phishing emails, suspicious URLs, and malware-related reports.

## Core behavior
- Stay evidence-based and concise.
- Start with a short verdict and severity.
- Separate observed facts from inference.
- If the artifact is incomplete, say what is missing.
- Do not overclaim certainty when evidence is thin.

## For each input type:

### Log files
Look for: authentication abuse, privilege escalation, lateral movement, suspicious processes, persistence, command execution, encoded payloads, beaconing, DNS anomalies, exfiltration.

### Phishing emails
Review: sender, reply-to, body, links, attachments, urgency language, credential prompts, brand impersonation.

### Malware artifacts
Look for: persistence, LOLBins, process trees, dropped files, registry changes, service creation, outbound callbacks.

## Output format:
1. **Verdict** (benign, suspicious, likely malicious, inconclusive)
2. **Severity** (low, medium, high, critical)
3. **Why** — 3-7 bullets
4. **IOCs** — indicators of compromise
5. **Likely technique** — MITRE-style behavior
6. **Next steps** — containment, validation, hunting actions

Be professional, direct, and concise.
"""


def analyze_artifact(artifact_text: str, artifact_type: str = "auto") -> dict:
    """
    Analyze a security artifact using Gemini Managed Agent.
    
    Args:
        artifact_text: The content to analyze
        artifact_type: Type of artifact (log, phishing_email, malware, url, or auto)
    
    Returns:
        dict with analysis results
    """
    
    if artifact_type == "auto":
        type_hint = "Determine the type of security artifact and analyze accordingly."
    else:
        type_hint = f"This is a {artifact_type.replace('_', ' ')}. Analyze accordingly."
    
    task = f"""
{type_hint}

ARTIFACT:
---
{artifact_text}
---

Provide a structured analysis with verdict, severity, evidence, IOCs, technique, and next steps.
"""
    
    try:
        # Call Gemini Managed Agent
        response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=f"{SYSTEM_PROMPT}\n\n{task}"
        )

        analysis_text = response.text

        result = {
        "analysis": analysis_text,
        "artifact_type": artifact_type,
        "status": "completed"
        }
        # Extract verdict and severity from analysis
        text_lower = analysis_text.lower()
        
        if "malicious" in text_lower:
            result["verdict"] = "likely_malicious"
            if "critical" in text_lower:
                result["severity"] = "critical"
            elif "high" in text_lower:
                result["severity"] = "high"
            else:
                result["severity"] = "medium"
        elif "suspicious" in text_lower:
            result["verdict"] = "suspicious"
            result["severity"] = "medium"
        elif "benign" in text_lower:
            result["verdict"] = "benign"
            result["severity"] = "low"
        else:
            result["verdict"] = "inconclusive"
            result["severity"] = "medium"
        
        return result
    
    except Exception as e:
        return {
            'error': str(e),
            'message': 'Agent analysis failed',
            'status': 'error'
        }


def analyze_log(log_content: str) -> dict:
    """Analyze a log file for security threats."""
    return analyze_artifact(log_content, "log")
if __name__ == "__main__":
    result = analyze_log("""
    Failed login from 192.168.1.100
    Failed login from 192.168.1.100
    Failed login from 192.168.1.100
    Successful login from 192.168.1.100
    """)

    print(result)


def analyze_email(email_content: str, subject: str = None, sender: str = None, urls: list = None) -> dict:
    """Analyze an email for phishing/security threats."""
    
    formatted_email = f"""
SUBJECT: {subject or '[No subject]'}
FROM: {sender or '[Unknown sender]'}

BODY:
{email_content}

URLS DETECTED: {', '.join(urls) if urls else '[None]'}
"""
    
    return analyze_artifact(formatted_email, "phishing_email")


def analyze_malware(report_content: str) -> dict:
    """Analyze a malware behavior report."""
    return analyze_artifact(report_content, "malware")


def check_interaction_status(interaction_id: str) -> dict:
    """Check the status of an ongoing analysis."""
    try:
        interaction = client.interactions.get(interaction_id)
        return {
            "interaction_id": interaction_id,
            "status": interaction.status,
            "output": interaction.output_text if interaction.status == "completed" else None
        }
    except Exception as e:
        return {
            'error': str(e),
            'status': 'error'
        }
    
