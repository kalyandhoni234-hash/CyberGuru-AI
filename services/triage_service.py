"""
Cybersecurity Triage Agent
Handles security artifact analysis using Gemini with function calling.

Gemini decides which threat-intel lookups and MITRE mappings to perform
based on what it finds in the artifact, rather than the pipeline
deciding for it ahead of time.
"""
import os
import re
from dotenv import load_dotenv

load_dotenv()
from google import genai
from google.genai import types

from utils.abuseipdb_tool import check_abuseipdb
from utils.virustotal_tool import check_virustotal_ip
from utils.mitre_mapper import lookup_mitre, extract_mitre_techniques


_GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not _GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY environment variable is not set")

client = genai.Client(api_key=_GEMINI_API_KEY)


SYSTEM_PROMPT = """# Cybersecurity Triage Agent

You analyze security-related artifacts: log files, phishing emails, suspicious URLs, and malware-related reports.

## Core behavior
- Stay evidence-based and concise.
- Start with a short verdict and severity.
- Separate observed facts from inference.
- If the artifact is incomplete, say what is missing.
- Do not overclaim certainty when evidence is thin.

## Tools available to you
- check_abuseipdb(ip): look up an IP's abuse reports and confidence score.
- check_virustotal_ip(ip): look up an IP's VirusTotal detection stats.
- lookup_mitre(technique): get the MITRE ATT&CK ID for a named technique
  (e.g. "brute force", "phishing", "powershell", "dns tunneling").

When the artifact contains IP addresses that are relevant to your analysis
(e.g. source of failed logins, C2 callbacks, suspicious connections), use
the threat-intel tools to check them BEFORE forming your verdict. Use the
results to support or adjust your assessment - e.g. a high AbuseIPDB
confidence score or VirusTotal malicious detections should increase your
confidence in a malicious verdict.

When you identify adversary behavior, call lookup_mitre with the technique
name to get the correct ATT&CK ID, and include it in your "Likely
technique" section using the format "T#### - Technique Name".

Not every artifact needs tool calls - if there are no IPs to check or no
clear technique, skip the tools and analyze directly.

## For each input type:

### Log files
Look for: authentication abuse, privilege escalation, lateral movement, suspicious processes, persistence, command execution, encoded payloads, beaconing, DNS anomalies, exfiltration.

### Phishing emails
Review: sender, reply-to, body, links, attachments, urgency language, credential prompts, brand impersonation.

### Malware artifacts
Look for: persistence, LOLBins, process trees, dropped files, registry changes, service creation, outbound callbacks.

## Output format (final answer, after any tool calls):
1. **Verdict** (benign, suspicious, likely malicious, inconclusive)
2. **Severity** (low, medium, high, critical)
3. **Why** — 3-7 bullets
4. **IOCs** — indicators of compromise
5. **Likely technique** — MITRE-style behavior, formatted as "T#### - Name"
6. **Next steps** — containment, validation, hunting actions

Be professional, direct, and concise.
"""


# --- Tool/function declarations for Gemini ---

_TOOLS = [
    types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="check_abuseipdb",
            description="Check an IP address's abuse reports and confidence score on AbuseIPDB.",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "ip": types.Schema(type=types.Type.STRING, description="The IP address to check")
                },
                required=["ip"]
            )
        ),
        types.FunctionDeclaration(
            name="check_virustotal_ip",
            description="Check an IP address's detection stats on VirusTotal.",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "ip": types.Schema(type=types.Type.STRING, description="The IP address to check")
                },
                required=["ip"]
            )
        ),
        types.FunctionDeclaration(
            name="lookup_mitre",
            description="Look up the MITRE ATT&CK ID and name for a named technique (e.g. 'brute force', 'phishing', 'powershell', 'dns tunneling').",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "technique": types.Schema(type=types.Type.STRING, description="The technique name")
                },
                required=["technique"]
            )
        ),
    ])
]

_TOOL_FUNCTIONS = {
    "check_abuseipdb": check_abuseipdb,
    "check_virustotal_ip": check_virustotal_ip,
    "lookup_mitre": lookup_mitre,
}

_VERDICT_VALUES = ["likely malicious", "suspicious", "inconclusive", "benign"]
_SEVERITY_VALUES = ["critical", "high", "medium", "low"]

MAX_TOOL_ITERATIONS = 6


def _extract_field(analysis_text, field_name, allowed_values):
    pattern = rf"{field_name}\**\s*[:\-]?\s*\(?\s*([a-zA-Z\s]+)"
    match = re.search(pattern, analysis_text, re.IGNORECASE)

    candidate = match.group(1).lower() if match else ""

    for value in allowed_values:
        if value in candidate:
            return value.replace(" ", "_") if field_name.lower() == "verdict" else value

    text_lower = analysis_text.lower()
    for value in allowed_values:
        if value in text_lower:
            return value.replace(" ", "_") if field_name.lower() == "verdict" else value

    return "inconclusive" if field_name.lower() == "verdict" else "medium"


def _run_tool_call(function_call):
    """Execute a single tool call requested by Gemini, return its result dict."""
    name = function_call.name
    args = dict(function_call.args) if function_call.args else {}

    func = _TOOL_FUNCTIONS.get(name)
    if func is None:
        return {"error": f"Unknown tool: {name}"}

    try:
        return func(**args)
    except Exception as e:
        return {"error": str(e)}


def analyze_artifact(artifact_text: str, artifact_type: str = "auto") -> dict:
    """
    Analyze a security artifact using Gemini with function calling.

    Gemini may call check_abuseipdb, check_virustotal_ip, and lookup_mitre
    as needed before producing its final structured analysis.

    Returns a dict with:
        analysis        - final analysis text
        artifact_type
        status           - "completed" or "error"
        verdict
        severity
        tool_calls       - list of {"name", "args", "result"} for tools Gemini used
        mitre_techniques - list of {"id", "name"} extracted from the analysis
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
Use the available tools to check any relevant IP addresses and to look up MITRE technique IDs
before giving your final answer.
"""

    contents = [
        types.Content(role="user", parts=[types.Part(text=f"{SYSTEM_PROMPT}\n\n{task}")])
    ]

    tool_calls_made = []

    try:
        for _ in range(MAX_TOOL_ITERATIONS):
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=contents,
                config=types.GenerateContentConfig(tools=_TOOLS)
            )

            if not response.candidates:
                return {
                    "error": "Empty response from model (no candidates)",
                    "message": "Agent analysis failed",
                    "status": "error"
                }

            candidate = response.candidates[0]
            parts = candidate.content.parts if candidate.content else []

            function_calls = [p.function_call for p in parts if getattr(p, "function_call", None)]

            if not function_calls:
                # No more tool calls - this is the final answer
                analysis_text = getattr(response, "text", None)

                if not analysis_text:
                    return {
                        "error": "Empty final response from model",
                        "message": "Agent analysis failed",
                        "status": "error"
                    }

                result = {
                    "analysis": analysis_text,
                    "artifact_type": artifact_type,
                    "status": "completed",
                    "tool_calls": tool_calls_made,
                }

                result["verdict"] = _extract_field(analysis_text, "Verdict", _VERDICT_VALUES)
                result["severity"] = _extract_field(analysis_text, "Severity", _SEVERITY_VALUES)
                result["mitre_techniques"] = extract_mitre_techniques(analysis_text)

                return result

            # Gemini wants to call one or more tools - append its turn,
            # execute the calls, and append the results as a new turn.
            contents.append(candidate.content)

            function_response_parts = []

            for fc in function_calls:
                tool_result = _run_tool_call(fc)

                tool_calls_made.append({
                    "name": fc.name,
                    "args": dict(fc.args) if fc.args else {},
                    "result": tool_result
                })

                function_response_parts.append(
                    types.Part(function_response=types.FunctionResponse(
                        name=fc.name,
                        response={"result": tool_result}
                    ))
                )

            contents.append(types.Content(role="user", parts=function_response_parts))

        # Hit MAX_TOOL_ITERATIONS without a final answer
        return {
            "error": f"Exceeded {MAX_TOOL_ITERATIONS} tool-call iterations without a final answer",
            "message": "Agent analysis failed",
            "status": "error",
            "tool_calls": tool_calls_made,
        }

    except Exception as e:
        return {
            "error": str(e),
            "message": "Agent analysis failed",
            "status": "error",
            "tool_calls": tool_calls_made,
        }


def analyze_log(log_content: str) -> dict:
    """Analyze a log file for security threats."""
    return analyze_artifact(log_content, "log")


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


if __name__ == "__main__":
    result = analyze_log("""
    Failed login from 185.220.101.45
    Failed login from 185.220.101.45
    Failed login from 185.220.101.45
    Successful login from 185.220.101.45
    """)

    print(result)