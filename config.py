import os

# ==========================
# GEMINI API
# ==========================

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL   = "gemini-2.5-flash"

if not API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not found")

API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{MODEL}:generateContent"
)
API_URL_STREAM = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{MODEL}:streamGenerateContent?alt=sse"
)

FLASH_LITE_MODEL = "gemini-2.0-flash-lite"
FLASH_LITE_API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{FLASH_LITE_MODEL}:generateContent"
)
FLASH_LITE_API_URL_STREAM = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{FLASH_LITE_MODEL}:streamGenerateContent?alt=sse"
)


# F-04: Do NOT bake the API key into a module-level dict.
# Module-level dicts are trivially serialised by loggers and error reporters
# (Sentry, Rollbar, stdout tracebacks) — any serialisation leaks the key.
# ─── Migration: replace every `from config import GEMINI_HEADERS` in
#     gemini_service.py with `from config import get_gemini_headers`, then
#     call get_gemini_headers() at the point each request is built. ───────
def get_gemini_headers() -> dict:
    """Return fresh Gemini request headers.  Never cache or log this dict."""
    return {
        "Content-Type": "application/json",
        "x-goog-api-key": os.getenv("GEMINI_API_KEY", ""),
    }


# ==========================
# GENERATION CONFIG
# ==========================

GENERATION_CONFIG = {
    "maxOutputTokens": 8192,
    "temperature": 0.7,
}

# ==========================
# INPUT / CONTENT LENGTH CAPS  (F-08)
# ==========================
# All length limits live here — change once, applies everywhere.
#
# Relationship:
#   MAX_INPUT_CHARS  ≤  MAX_HISTORY_MSG_CHARS
#   A message stored in history may have been pasted (longer than typed),
#   so the history cap is intentionally wider than the intake cap.
#   Trimming happens at the history-write stage, not at intake.

# User chat message — enforced in the UI and re-validated server-side.
MAX_INPUT_CHARS       = 4_000

# Triage artifacts (logs, emails, malware reports) are legitimately longer
# than chat messages but still need a hard ceiling — unbounded artifact text
# fed into the agent's multi-round tool loop is a cost/latency-amplification
# DoS vector without one.
MAX_ARTIFACT_CHARS    = 20_000

# Per-message cap applied when serialising history for the model context.
MAX_HISTORY_MSG_CHARS = 8_000

# Rolling history window — max round-trips kept in-context.
MAX_HISTORY_TURNS     = 10

# Total byte budget for the serialised history payload.
MAX_HISTORY_BYTES     = 60_000


# ==========================
# SYSTEM INSTRUCTION
# ==========================

SYSTEM_INSTRUCTION = """
You are CyberGuru AI, an expert cybersecurity mentor and educator.

## SCOPE
- Answer cybersecurity and computer networking -related questions only.
- For clearly unrelated questions, reply: "I am CyberGuru AI and can only assist with cybersecurity topics."
- For casual greetings (hi, how are you, etc.), respond warmly and briefly, then invite a cybersecurity question.

## ETHICS
- Never encourage illegal hacking, unauthorized access, malware deployment, credential theft, or any harmful activity.
- When covering offensive security techniques, frame everything around education, defense, detection, and ethical/authorized use.

## RESPONSE STYLE
- Be concise by default. Match answer length to the complexity of the question — a simple question gets a short answer, a deep question gets a thorough one.
- If an answer would exceed ~500 words and the user did not ask for detail, first ask: "Would you like a detailed explanation?"
- Do NOT write textbook-style walls of text. Prefer practical, actionable explanations.
- Use numbered lists (1. 2. 3.) rather than bullet asterisks (*) for multi-point answers.
- Use headings (## or ###) only when the response has multiple distinct sections that benefit from separation.
- Use sparingly: 🛡️ ⚠️ 🔍 ✅ — one or two per response max, never decoratively on every line.

## ANSWER STRUCTURE (for technical topics)
When explaining a cybersecurity concept, use this flow naturally (not as rigid headers):
1. What it is (definition)
2. How it works / real example
3. Why it matters
4. How to defend against it / mitigate it

## CODE & COMMANDS
- Explain what each part does.
- Note risks or misuse potential where relevant.
- Always wrap commands/code in code blocks.

## SIGN-OFF
End every response with exactly this line, on its own line:
──────
🛡️ CyberGuru AI
"""

# ==========================
# GROUNDING
# ==========================

GROUNDING_KEYWORDS = [
    "cve", "vulnerability", "vulnerabilities", "exploit", "zero-day", "0-day",
    "patch", "advisory", "nvd", "nist",
    "latest", "recent", "new", "news", "today", "this week", "this month",
    "current", "just released", "announced", "update", "breach", "attack",
    "ransomware", "apt ", "threat actor", "campaign", "incident",
    "version", "release", "changelog",
]

GOOGLE_SEARCH_TOOL = {"google_search": {}}

# ==========================
# RETRY CONFIG  (F-06)
# ==========================
# Service-layer back-off formula (exponential + jitter):
#
#   delay = min(BASE_BACKOFF * 2 ** attempt, MAX_BACKOFF)
#           + random.uniform(0, MAX_JITTER)
#
# Jitter prevents thundering-herd retries — multiple gunicorn workers that
# all hit a transient Gemini 429/503 will NOT retry in lockstep.

MAX_RETRIES  = 3
BASE_BACKOFF = 5   # seconds — base for exponential back-off
MAX_BACKOFF  = 30  # seconds — cap so retries never stall a worker indefinitely
MAX_JITTER   = 2   # seconds — uniform random jitter added to every back-off interval
