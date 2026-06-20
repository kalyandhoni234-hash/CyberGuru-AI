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

FLASH_LITE_MODEL = "gemini-3.1-flash-lite"
FLASH_LITE_API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{FLASH_LITE_MODEL}:generateContent"
)
FLASH_LITE_API_URL_STREAM = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{FLASH_LITE_MODEL}:streamGenerateContent?alt=sse"
)

GEMINI_HEADERS = {
    "Content-Type": "application/json",
    "x-goog-api-key": API_KEY,
}

# ==========================
# GENERATION CONFIG
# ==========================

GENERATION_CONFIG = {
    "maxOutputTokens": 8192,
    "temperature": 0.7,
}

MAX_HISTORY_TURNS    = 10
MAX_HISTORY_BYTES    = 60_000
MAX_HISTORY_MSG_CHARS = 8000
MAX_INPUT_CHARS      = 4000

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
# RETRY CONFIG
# ==========================

MAX_RETRIES  = 3
BASE_BACKOFF = 5
