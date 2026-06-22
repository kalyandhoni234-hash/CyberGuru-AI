"""
Cybersecurity Triage Agent
Analyzes security artifacts using Gemini with function calling.
 
FIX #3: System prompt is now passed as system_instruction in GenerateContentConfig
instead of being prepended to the first user message. This is the correct way to
set persistent model instructions with the Google GenAI SDK — it reduces prompt
injection risk and improves model compliance.
 
FIX #6: Verdict and severity are now extracted from a structured JSON block that
Gemini is explicitly asked to append to its response, instead of relying on fragile
regex parsing of free-form text. Regex fallback is kept for robustness.
 
FIX #2 (partial — error detail sanitisation): Internal error messages from tool
calls are now logged server-side but not propagated to the caller in full detail.
"""
import os
import re
import json
import logging
from dotenv import load_dotenv
 
load_dotenv()
from google import genai
from google.genai import types
 
from utils.abuseipdb_tool import check_abuseipdb
from utils.virustotal_tool import check_virustotal_ip
from utils.mitre_mapper import lookup_mitre, extract_mitre_techniques
 
logger = logging.getLogger(__name__)
 
_GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not _GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY environment variable is not set")
 
client = genai.Client(api_key=_GEMINI_API_KEY)
 
 
# FIX #3: This is now passed as system_instruction, not injected into user content.
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
results to support or adjust your assessment.
 
When you identify adversary behavior, call lookup_mitre with the technique
name to get the correct ATT&CK ID, and include it using the format "T#### - Technique Name".
 
Not every artifact needs tool calls — if there are no IPs to check or no
clear technique, skip the tools and analyze directly.
 
## For each input type:
 
### Log files
Look for: authentication abuse, privilege escalation, lateral movement, suspicious processes,
persistence, command execution, encoded payloads, beaconing, DNS anomalies, exfiltration.
 
### Phishing emails
Review: sender, reply-to, body, links, attachments, urgency language, credential prompts,
brand impersonation.
 
### Malware artifacts
Look for: persistence, LOLBins, process trees, dropped files, registry changes,
service creation, outbound callbacks.
 
## Output format (final answer, after any tool calls):
1. **Verdict** (benign, suspicious, likely malicious, inconclusive)
2. **Severity** (low, medium, high, critical)
3. **Why** — 3-7 bullets
4. **IOCs** — indicators of compromise
5. **Likely technique** — MITRE-style behavior, formatted as "T#### - Name"
6. **Next steps** — containment, validation, hunting actions
 
After your narrative analysis, append a machine-readable JSON block on its own line
so the application can parse verdict and severity reliably. Format it exactly like this:
 
```json
{"verdict": "<benign|suspicious|likely_malicious|inconclusive>", "severity": "<low|medium|high|critical>"}
```
 
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
            description="Look up the MITRE ATT&CK ID and name for a named technique.",
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
 
# FIX: Disable Gemini's default safety filters for the categories that fire on
# security-research content (phishing bodies, malware reports, threat-intel).
# Without this, the model returns no candidates for legitimate triage inputs —
# e.g. a phishing email body triggers HARASSMENT/DANGEROUS_CONTENT blocks.
# BLOCK_NONE tells the API to score but never suppress; the analyst's system
# prompt (passed as system_instruction) already scopes the task to defence.
_SAFETY_SETTINGS = [
    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",        threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT",  threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT",  threshold="BLOCK_NONE"),
]
 
_VERDICT_VALUES = ["likely malicious", "suspicious", "inconclusive", "benign"]
_SEVERITY_VALUES = ["critical", "high", "medium", "low"]
 
MAX_TOOL_ITERATIONS = 6
 
# ─────────────────────────────────────────────
# FIX #6: Structured JSON verdict extraction
# ─────────────────────────────────────────────
 
_JSON_BLOCK_RE = re.compile(
    r"```json\s*(\{[^`]+\})\s*```",
    re.IGNORECASE | re.DOTALL
)
 
_VERDICT_NORMALISE = {
    "likely malicious":  "likely_malicious",
    "likely_malicious":  "likely_malicious",
    "suspicious":        "suspicious",
    "inconclusive":      "inconclusive",
    "benign":            "benign",
}
 
_SEVERITY_NORMALISE = {v: v for v in _SEVERITY_VALUES}
 
 
def _extract_structured(analysis_text: str) -> tuple[str, str]:
    """
    Primary path: parse the JSON block Gemini was asked to append.
    Returns (verdict, severity).
 
    Falls back to the original regex scan of free-form text if the JSON
    block is absent or malformed — keeping behaviour for edge cases where
    the model omits the block.
    """
    # --- Primary: JSON block ---
    match = _JSON_BLOCK_RE.search(analysis_text)
    if match:
        try:
            data = json.loads(match.group(1))
            raw_verdict  = str(data.get("verdict",  "")).lower().strip()
            raw_severity = str(data.get("severity", "")).lower().strip()
            verdict  = _VERDICT_NORMALISE.get(raw_verdict,  "inconclusive")
            severity = _SEVERITY_NORMALISE.get(raw_severity, "medium")
            return verdict, severity
        except (json.JSONDecodeError, AttributeError):
            logger.warning("Triage: JSON block present but failed to parse — falling back to regex")
 
    # --- Fallback: regex scan ---
    return _extract_field_regex(analysis_text)
 
 
def _extract_field_regex(analysis_text: str) -> tuple[str, str]:
    """Original regex extraction as a fallback."""
    verdict  = _regex_field(analysis_text, "Verdict",  _VERDICT_VALUES, "inconclusive")
    severity = _regex_field(analysis_text, "Severity", _SEVERITY_VALUES, "medium")
    return verdict, severity
 
 
def _regex_field(text: str, field_name: str, allowed: list, default: str) -> str:
    pattern = rf"{field_name}\**\s*[:\-]?\s*\(?\s*([a-zA-Z\s_]+)"
    match = re.search(pattern, text, re.IGNORECASE)
    candidate = match.group(1).lower().strip() if match else ""
 
    for value in allowed:
        if value in candidate:
            normalised = value.replace(" ", "_") if field_name.lower() == "verdict" else value
            return normalised
 
    text_lower = text.lower()
    for value in allowed:
        if value in text_lower:
            return value.replace(" ", "_") if field_name.lower() == "verdict" else value
 
    return default
 
 
# ─────────────────────────────────────────────
# Tool execution
# ─────────────────────────────────────────────
 
def _run_tool_call(function_call):
    """
    Execute a single tool call, returning its result dict.
    Errors are logged server-side; only a safe sentinel is returned to Gemini.
    """
    name = function_call.name
    args = dict(function_call.args) if function_call.args else {}
 
    func = _TOOL_FUNCTIONS.get(name)
    if func is None:
        logger.warning("Triage: unknown tool requested: %s", name)
        return {"error": "Tool not available"}
 
    try:
        return func(**args)
    except Exception as exc:
        # FIX #2 (tool level): log full detail server-side, return a safe stub.
        logger.exception("Triage: tool %s raised an exception", name)
        return {"error": "Tool lookup failed", "tool": name}
 
 
# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────
 
def analyze_artifact(artifact_text: str, artifact_type: str = "auto") -> dict:
    """
    Analyze a security artifact using Gemini with function calling.
 
    Returns a dict with:
        analysis        — final analysis text (narrative)
        artifact_type
        status          — "completed" or "error"
        verdict
        severity
        tool_calls      — list of {name, args, result}
        mitre_techniques— list of {id, name}
    """
    if artifact_type == "auto":
        type_hint = "Determine the type of security artifact and analyze accordingly."
    else:
        type_hint = f"This is a {artifact_type.replace('_', ' ')}. Analyze accordingly."
 
    task = f"""{type_hint}
 
ARTIFACT:
---
{artifact_text}
---
 
Provide a structured analysis with verdict, severity, evidence, IOCs, technique, and next steps.
Use the available tools to check any relevant IP addresses and to look up MITRE technique IDs
before giving your final answer.
Remember to append the machine-readable JSON block at the end of your response.
"""
 
    # FIX #3: system_instruction is now a proper GenerateContentConfig field,
    # not prepended to the user message. This is the correct SDK usage.
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=_TOOLS,
        # FIX: Pass security-research safety settings so phishing/malware
        # content is not blocked by Gemini's default content filters.
        safety_settings=_SAFETY_SETTINGS,
    )
 
    contents = [
        types.Content(role="user", parts=[types.Part(text=task)])
    ]
 
    tool_calls_made = []
 
    try:
        for iteration in range(MAX_TOOL_ITERATIONS):
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=contents,
                config=config,
            )
 
            if not response.candidates:
                # FIX: Log prompt_feedback when the request itself is blocked
                # (e.g. prompt-level safety rejection before any candidate is
                # produced). Without this the caller only sees "no candidates".
                pf = getattr(response, "prompt_feedback", None)
                block_reason = getattr(pf, "block_reason", None) if pf else None
                logger.error(
                    "Triage: no candidates returned (iteration %d); "
                    "prompt_feedback.block_reason=%s",
                    iteration, block_reason,
                )
                return {
                    "error": "Empty response from model (no candidates)",
                    "message": "Agent analysis failed",
                    "status": "error",
                    "tool_calls": tool_calls_made,
                }
 
            candidate = response.candidates[0]
 
            # FIX: Always log finish_reason so safety blocks and stop reasons
            # are visible in server logs instead of being silently swallowed.
            # finish_reason is an enum — str() gives a readable name.
            finish_reason = getattr(candidate, "finish_reason", None)
            if finish_reason is not None:
                finish_reason_str = str(finish_reason)
                # Safety blocks surface as SAFETY; log them at WARNING so they
                # are easy to grep even when the rest of the pipeline succeeds.
                if "SAFETY" in finish_reason_str:
                    logger.warning(
                        "Triage: candidate finish_reason=%s (iteration %d) — "
                        "safety_ratings=%s",
                        finish_reason_str, iteration,
                        getattr(candidate, "safety_ratings", []),
                    )
                else:
                    logger.debug(
                        "Triage: candidate finish_reason=%s (iteration %d)",
                        finish_reason_str, iteration,
                    )
 
            parts = candidate.content.parts if candidate.content else []
            function_calls = [p.function_call for p in parts if getattr(p, "function_call", None)]
 
            if not function_calls:
                # No more tool calls — this is the final answer.
                # FIX: response.text is a property that raises ValueError when
                # Gemini's safety filters block the response. getattr() does NOT
                # catch property-level exceptions, so we use try/except instead.
                try:
                    analysis_text = response.text
                except ValueError as exc:
                    # Safety-blocked or malformed finish — log finish_reason for
                    # context (already logged above, but include it here too so
                    # the two log lines are easy to correlate).
                    logger.warning(
                        "Triage: response.text raised ValueError (finish_reason=%s, '%s')",
                        finish_reason, exc,
                    )
                    analysis_text = None
 
                if not analysis_text:
                    return {
                        "error": "Empty final response from model",
                        "message": "Agent analysis failed",
                        "status": "error",
                        "tool_calls": tool_calls_made,
                    }
 
                # FIX #6: structured extraction first, regex fallback second.
                verdict, severity = _extract_structured(analysis_text)
 
                return {
                    "analysis":        analysis_text,
                    "artifact_type":   artifact_type,
                    "status":          "completed",
                    "verdict":         verdict,
                    "severity":        severity,
                    "tool_calls":      tool_calls_made,
                    "mitre_techniques": extract_mitre_techniques(analysis_text),
                }
 
            # Gemini wants to call tools — append its turn, execute, append results.
            contents.append(candidate.content)
            function_response_parts = []
 
            for fc in function_calls:
                tool_result = _run_tool_call(fc)
                tool_calls_made.append({
                    "name":   fc.name,
                    "args":   dict(fc.args) if fc.args else {},
                    "result": tool_result,
                })
                function_response_parts.append(
                    types.Part(function_response=types.FunctionResponse(
                        name=fc.name,
                        response={"result": tool_result}
                    ))
                )
 
            contents.append(types.Content(role="user", parts=function_response_parts))
 
        # Exhausted MAX_TOOL_ITERATIONS without a final text answer.
        return {
            "error": f"Exceeded {MAX_TOOL_ITERATIONS} tool-call iterations without a final answer",
            "message": "Agent analysis failed",
            "status": "error",
            "tool_calls": tool_calls_made,
        }
 
    except Exception as exc:
        # FIX #2 (outer level): log full traceback, return safe generic message.
        logger.exception("Triage: analyze_artifact raised an unhandled exception")
        return {
            "error": "Internal analysis error",
            "message": "Agent analysis failed",
            "status": "error",
            "tool_calls": tool_calls_made,
        }
 
 
# ─────────────────────────────────────────────
# Convenience wrappers
# ─────────────────────────────────────────────
 
def analyze_log(log_content: str) -> dict:
    return analyze_artifact(log_content, "log")
 
 
def analyze_email(
    email_content: str,
    subject: str = None,
    sender: str = None,
    urls: list = None,
) -> dict:
    formatted = f"""SUBJECT: {subject or '[No subject]'}
FROM: {sender or '[Unknown sender]'}
 
BODY:
{email_content}
 
URLS DETECTED: {', '.join(urls) if urls else '[None]'}
"""
    return analyze_artifact(formatted, "phishing_email")
 
 
def analyze_malware(report_content: str) -> dict:
    return analyze_artifact(report_content, "malware")
 
 
if __name__ == "__main__":
    result = analyze_log("""
    Failed login from 185.220.101.45
    Failed login from 185.220.101.45
    Failed login from 185.220.101.45
    Successful login from 185.220.101.45
    """)
    print(result)