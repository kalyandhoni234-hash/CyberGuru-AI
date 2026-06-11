from dotenv import load_dotenv
load_dotenv()  # load .env before ANY os.getenv() call
import os
import re
import json
import time
import psycopg2
import psycopg2.extras
import requests
from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from functools import wraps

print("RUNNING FILE:", __file__)
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False   # preserve emojis in jsonify() responses
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))  # set FLASK_SECRET_KEY in production!

# ── Session cookie config ──────────────────────────────────────
# SameSite=Lax allows the cookie to be sent after Google's redirect
# Secure=False for local dev (http); set to True on Render (https)
IS_PRODUCTION = os.getenv("RENDER", False)  # Render sets this automatically
app.config.update(
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = bool(IS_PRODUCTION),
    SESSION_COOKIE_HTTPONLY = True,
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30,  # 30 days
)
CORS(app, supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://",   # swap to "redis://..." in production
)

@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({
        "reply": f"⚠️ Too many requests — {e.description}. Please slow down and try again shortly.",
        "rate_limited": True,
        "retry_after": 60
    }), 429

# ==========================
# GOOGLE OAUTH + POSTGRES AUTH
# ==========================

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

DATABASE_URL = os.getenv("DATABASE_URL")  # Neon connection string
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not found")

def get_db():
    """Open a new Postgres connection. Use as a context manager."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id         SERIAL PRIMARY KEY,
                    google_id  TEXT UNIQUE NOT NULL,
                    email      TEXT NOT NULL,
                    name       TEXT,
                    avatar     TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
        conn.commit()

init_db()

def upsert_user(google_id, email, name, avatar):
    """Insert or update a user row, return the row as a dict."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (google_id, email, name, avatar)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (google_id) DO UPDATE SET
                    email  = EXCLUDED.email,
                    name   = EXCLUDED.name,
                    avatar = EXCLUDED.avatar
                RETURNING *
            """, (google_id, email, name, avatar))
            conn.commit()
            return cur.fetchone()

def login_required(f):
    """Decorator: reject unauthenticated API calls with 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Authentication required", "auth_required": True}), 401
        return f(*args, **kwargs)
    return decorated



# Always serialize JSON with Unicode intact (fixes emoji encoding in SSE streams)
def jdump(obj):
    return json.dumps(obj, ensure_ascii=False)

# ==========================
# CONFIGURATION
# ==========================

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = "gemini-2.5-flash"
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

# Common headers — keeps the API key out of URLs (and therefore out of logs)
GEMINI_HEADERS = {
    "Content-Type": "application/json",
    "x-goog-api-key": API_KEY,
}

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

# Max messages to send as history (keeps token usage reasonable)
MAX_HISTORY_TURNS = 10

# Applied to every Gemini request — prevents cut-off responses
GENERATION_CONFIG = {
    "maxOutputTokens": 8192,
    "temperature": 0.7,
}

# ==========================
# INPUT SANITIZATION
# ==========================

MAX_INPUT_CHARS = 4000   # mirrors frontend char counter

def sanitize_input(text: str) -> str:
    """
    Strip null bytes and other non-printable control characters,
    then hard-cap length to MAX_INPUT_CHARS.
    This runs server-side regardless of what the frontend enforces.
    """
    # Remove null bytes and most C0/C1 control chars (keep \t \n \r)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    # Hard length cap
    if len(cleaned) > MAX_INPUT_CHARS:
        cleaned = cleaned[:MAX_INPUT_CHARS]
    return cleaned.strip()


# ==========================
# GROUNDING CONFIG
# ==========================

# Keywords that suggest real-time info is needed — triggers Google Search grounding
GROUNDING_KEYWORDS = [
    # CVE / vulnerability
    "cve", "vulnerability", "vulnerabilities", "exploit", "zero-day", "0-day",
    "patch", "advisory", "nvd", "nist",
    # News & recent events
    "latest", "recent", "new", "news", "today", "this week", "this month",
    "current", "just released", "announced", "update", "breach", "attack",
    # Specific threat actors / campaigns
    "ransomware", "apt ", "threat actor", "campaign", "incident",
    # Tools / releases
    "version", "release", "changelog",
]

GOOGLE_SEARCH_TOOL = {"google_search": {}}

def needs_grounding(message: str) -> bool:
    """Return True if the message likely needs real-time information."""
    lower = message.lower()
    return any(kw in lower for kw in GROUNDING_KEYWORDS)


# ==========================
# RETRY HELPER
# ==========================

MAX_RETRIES = 3          # number of retry attempts on 429 / 503
BASE_BACKOFF = 5         # seconds to wait before first retry (doubles each time)

def gemini_post(url, payload, stream=False, timeout=60):
    """
    POST to Gemini with exponential backoff on 429 (rate limit) and 503 (unavailable).
    Returns the requests.Response object on success, or raises on final failure.
    Raises GeminiRateLimitError or GeminiServiceError for callers to handle cleanly.
    """
    last_status = None
    for attempt in range(MAX_RETRIES):
        resp = requests.post(
            url,
            json=payload,
            headers=GEMINI_HEADERS,
            timeout=timeout,
            stream=stream,
        )
        last_status = resp.status_code

        if resp.status_code == 200:
            return resp

        if resp.status_code == 429:
            # Check if Gemini sent a retry-after header
            retry_after = int(resp.headers.get("Retry-After", 0))
            wait = retry_after if retry_after > 0 else BASE_BACKOFF * (2 ** attempt)
            print(f"[Retry {attempt+1}/{MAX_RETRIES}] 429 rate limit — waiting {wait}s")
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiRateLimitError()

        elif resp.status_code == 503:
            wait = BASE_BACKOFF * (2 ** attempt)
            print(f"[Retry {attempt+1}/{MAX_RETRIES}] 503 unavailable — waiting {wait}s")
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiServiceError(last_status)

        else:
            # 4xx other than 429 — don't retry
            raise GeminiServiceError(last_status)

    raise GeminiServiceError(last_status)


class GeminiRateLimitError(Exception):
    pass

class GeminiServiceError(Exception):
    def __init__(self, status_code=None):
        self.status_code = status_code
        super().__init__(f"Gemini API error {status_code}")


ALLOWED_HISTORY_ROLES = {"user", "bot"}
MAX_HISTORY_MSG_CHARS = 8000   # per-message cap; prevents one giant history entry

def validate_history(raw_history) -> list:
    """
    Sanitize client-supplied history before it reaches Gemini.
    - Rejects non-list input entirely.
    - Drops entries with invalid/missing roles (only 'user' and 'bot' allowed).
    - Drops entries with non-string or empty text.
    - Truncates each entry's text to MAX_HISTORY_MSG_CHARS.
    - Runs sanitize_input on every entry so control chars and
      length limits are enforced consistently with new messages.
    Returns a clean list safe to pass to build_contents().
    """
    if not isinstance(raw_history, list):
        return []

    clean = []
    for entry in raw_history:
        if not isinstance(entry, dict):
            continue
        role = entry.get("role", "")
        text = entry.get("text", "")
        # Reject unknown roles — prevents injecting 'model' or 'system' turns
        if role not in ALLOWED_HISTORY_ROLES:
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        clean.append({
            "role": role,
            "text": sanitize_input(text[:MAX_HISTORY_MSG_CHARS]),
        })

    return clean


def build_contents(history, new_message):
    """
    Convert frontend history format to Gemini contents array.
    history = [{"role": "user"|"bot", "text": "..."}]
    Gemini expects role = "user" | "model"
    Keeps last MAX_HISTORY_TURNS pairs (user+bot = 1 turn).
    """
    contents = []

    # Trim to last N turns (each turn = user + bot message = 2 items)
    max_msgs = MAX_HISTORY_TURNS * 2
    trimmed = history[-max_msgs:] if len(history) > max_msgs else history

    # Hard cap: if the accumulated history text exceeds ~60 KB, drop oldest
    # entries until it fits. Prevents prompt-stuffing via large histories.
    MAX_HISTORY_BYTES = 60_000
    while trimmed:
        total = sum(len(m.get("text", "")) for m in trimmed)
        if total <= MAX_HISTORY_BYTES:
            break
        trimmed = trimmed[2:]  # drop oldest turn (user + bot pair)

    for msg in trimmed:
        role = msg.get("role", "")
        text = msg.get("text", "")
        if not role or not isinstance(text, str):
            continue  # skip malformed history entries
        # Sanitize each history entry too — the client can't be trusted
        text = sanitize_input(text)
        gemini_role = "model" if role == "bot" else "user"
        contents.append({
            "role": gemini_role,
            "parts": [{"text": text}]
        })

    # Append the new user message
    contents.append({
        "role": "user",
        "parts": [{"text": new_message}]
    })

    return contents

# Allowlist of quiz topics — prevents prompt injection via /quiz <payload>
QUIZ_TOPIC_ALLOWLIST = {
    "sql injection", "xss", "cross-site scripting", "malware", "phishing",
    "network security", "cryptography", "encryption", "ransomware", "firewall",
    "penetration testing", "owasp", "owasp top 10", "buffer overflow",
    "social engineering", "zero-day", "zero day", "ddos", "man in the middle",
    "mitm", "authentication", "authorization", "csrf", "cross-site request forgery",
    "idor", "ssrf", "xxe", "command injection", "path traversal", "jwt",
    "vpn", "ids", "ips", "siem", "threat modelling", "threat modeling",
    "incident response", "forensics", "reverse engineering", "web security",
    "cloud security", "iot security", "mobile security", "apt", "rootkit",
    "keylogger", "botnet", "spyware", "trojan", "worm", "virus",
}

MAX_QUIZ_TOPIC_LEN = 60   # characters

def sanitize_quiz_topic(raw_topic: str) -> str | None:
    """
    Validate and normalize a quiz topic against the allowlist.
    Returns the cleaned topic string on success, or None if the topic
    is not recognized — indicating a likely injection attempt.
    """
    topic = raw_topic.strip()[:MAX_QUIZ_TOPIC_LEN]
    # Strip any characters that don't belong in a topic name
    topic = re.sub(r'[^\w\s\-]', '', topic).strip()
    if not topic:
        return None
    # Case-insensitive allowlist check — exact match or substring of an allowed topic
    lower = topic.lower()
    if lower in QUIZ_TOPIC_ALLOWLIST:
        return topic
    # Allow partial matches so "sql" matches "sql injection", etc.
    if any(lower in allowed or allowed in lower for allowed in QUIZ_TOPIC_ALLOWLIST):
        return topic
    return None   # not recognized — reject


def build_quiz_prompt(topic):
    return f"""
Generate a professional cybersecurity quiz.

Topic: {topic}

Rules:
- Create exactly 5 multiple-choice questions.
- Each question must have 4 options (A, B, C, D).
- Show the correct answer.
- Give a short explanation.
- Use markdown formatting.

Format:

# {topic.title()} Quiz

## Question 1

Question text

A) Option A
B) Option B
C) Option C
D) Option D

**Answer:** B

**Explanation:** Short explanation.

Repeat for 5 questions.
"""

# ==========================
# AUTH ROUTES
# ==========================

@app.route("/auth/login")
def auth_login():
    """Redirect the browser to Google's OAuth consent screen."""
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    """Google redirects here after user approves. Exchange code → tokens → user info."""
    token = google.authorize_access_token()
    userinfo = token.get("userinfo") or google.userinfo()
    google_id = userinfo["sub"]
    email     = userinfo.get("email", "")
    name      = userinfo.get("name", email)
    avatar    = userinfo.get("picture", "")

    user = upsert_user(google_id, email, name, avatar)

    session.permanent = True
    session["user"] = {
        "id":     user["id"],
        "google_id": google_id,
        "email":  email,
        "name":   name,
        "avatar": avatar,
    }
    return redirect("/")

@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/auth/me")
def auth_me():
    """Returns current session user, or 401 if not logged in."""
    user = session.get("user")
    if not user:
        return jsonify({"user": None}), 401
    return jsonify({"user": user})

# ==========================
# HEALTH CHECK
# ==========================

@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ==========================
# CHAT ROUTE (non-streaming, kept for fallback)
# ==========================

@app.route("/chat", methods=["POST"])
@limiter.limit("30 per minute; 200 per day")
@login_required
def chat():
    try:
        data = request.get_json()
        user_message = sanitize_input(data.get("message", ""))
        history       = validate_history(data.get("history", []))

        if not user_message:                          # ← check FIRST
            return jsonify({"reply": "Please enter a message."}), 400

        quiz_mode = False
        quiz_topic = ""
        if user_message.lower().startswith("/quiz"):
            quiz_mode = True
            quiz_topic = user_message[5:].strip()

        if quiz_mode:
            if not quiz_topic:
                return jsonify({
                    "reply": "⚠️ Please provide a topic.\n\nExample:\n/quiz sql injection"
                })
            safe_topic = sanitize_quiz_topic(quiz_topic)
            if not safe_topic:
                return jsonify({
                    "reply": (
                        "⚠️ That topic isn't in the quiz library.\n\n"
                        "Try one of: SQL Injection, XSS, Malware, Phishing, "
                        "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                        "Buffer Overflow, Social Engineering, or another cybersecurity topic."
                    )
                })
            user_message = build_quiz_prompt(safe_topic)

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

        # Add Google Search grounding for real-time queries
        if needs_grounding(user_message):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        response = gemini_post(API_URL, payload, timeout=30)
        response_data = response.json()
        bot_reply = response_data["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"reply": bot_reply})

    except GeminiRateLimitError:
        return jsonify({"reply": "⚠️ Gemini rate limit reached. Please wait a moment and try again."}), 429
    except GeminiServiceError as e:
        return jsonify({"reply": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}), 503
    except requests.exceptions.Timeout:
        return jsonify({"reply": "⚠️ Request timed out."}), 500
    except requests.exceptions.RequestException:
        return jsonify({"reply": "⚠️ Unable to reach Gemini API."}), 500
    except KeyError:
        return jsonify({"reply": "⚠️ Unexpected response format from Gemini API."}), 500
    except Exception as e:
        print("GEMINI ERROR:", e)
        return jsonify({"reply": f"⚠️ Server Error: {str(e)}"}), 500


# ==========================
# STREAMING CHAT ROUTE
# ==========================

@app.route("/chat-stream", methods=["POST"])
@limiter.limit("30 per minute; 200 per day")
@login_required
def chat_stream():
    try:
        data = request.get_json()
        user_message = sanitize_input(data.get("message", ""))
        history      = validate_history(data.get("history", []))

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        # ── Quiz mode (mirrors /chat handling) ──
        if user_message.lower().startswith("/quiz"):
            quiz_topic = user_message[5:].strip()
            if not quiz_topic:
                def no_topic():
                    yield ("data: " + jdump({"token": "⚠️ Please provide a topic.\n\nExample:\n`/quiz sql injection`"}) + "\n\n").encode("utf-8")
                    yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")
                return Response(stream_with_context(no_topic()), content_type="text/event-stream; charset=utf-8")
            safe_topic = sanitize_quiz_topic(quiz_topic)
            if not safe_topic:
                def bad_topic():
                    msg = (
                        "⚠️ That topic isn't in the quiz library.\n\n"
                        "Try one of: SQL Injection, XSS, Malware, Phishing, "
                        "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                        "Buffer Overflow, Social Engineering, or another cybersecurity topic."
                    )
                    yield ("data: " + jdump({"token": msg}) + "\n\n").encode("utf-8")
                    yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")
                return Response(stream_with_context(bad_topic()), content_type="text/event-stream; charset=utf-8")
            user_message = build_quiz_prompt(safe_topic)

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

        # Add Google Search grounding for real-time queries
        use_grounding = needs_grounding(user_message)
        if use_grounding:
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        # Open a streaming request to Gemini (with retry on 429/503)
        gemini_resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=60)

        def generate():
            grounding_meta = None  # collects groundingMetadata from last chunk

            # Tell the frontend we're hitting Google Search before any token arrives
            if use_grounding:
                yield ("data: " + jdump({"status": "searching"}) + "\n\n").encode("utf-8")

            for raw_line_bytes in gemini_resp.iter_lines():
                raw_line = raw_line_bytes.decode("utf-8") if isinstance(raw_line_bytes, bytes) else raw_line_bytes
                if not raw_line:
                    continue
                if raw_line.startswith("data:"):
                    json_str = raw_line[5:].strip()
                    if json_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(json_str)
                        candidate = chunk.get("candidates", [{}])[0]

                        text_piece = (
                            candidate.get("content", {})
                                     .get("parts", [{}])[0]
                                     .get("text", "")
                        )
                        if text_piece:
                            yield ("data: " + jdump({"token": text_piece}) + "\n\n").encode("utf-8")

                        # Capture grounding metadata whenever present
                        if "groundingMetadata" in candidate:
                            grounding_meta = candidate["groundingMetadata"]

                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue

            # After stream ends, send grounding sources as a separate event
            if grounding_meta:
                sources = []
                for chunk in grounding_meta.get("groundingChunks", []):
                    web = chunk.get("web", {})
                    if web.get("uri") and web.get("title"):
                        sources.append({
                            "title": web["title"],
                            "uri":   web["uri"],
                        })
                queries = grounding_meta.get("webSearchQueries", [])
                rendered = grounding_meta.get("searchEntryPoint", {}).get("renderedContent", "")
                if sources or rendered:
                    yield ("data: " + jdump({
                        "grounding": {
                            "sources":  sources,
                            "queries":  queries,
                            "rendered": rendered,
                        }
                    }) + "\n\n").encode("utf-8")

            yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")

        return Response(
            stream_with_context(generate()),
            content_type="text/event-stream; charset=utf-8",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )

    except GeminiRateLimitError:
        def rate_err():
            yield ("data: " + jdump({"rate_limited": True, "retry_after": 60, "error": "⚠️ Gemini rate limit reached after retries. Please wait a minute and try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(rate_err()), content_type="text/event-stream; charset=utf-8")

    except GeminiServiceError as e:
        def svc_err():
            yield ("data: " + jdump({"error": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(svc_err()), content_type="text/event-stream; charset=utf-8")

    except requests.exceptions.Timeout:
        def timeout_err():
            yield ("data: " + jdump({"error": "⚠️ Request timed out."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(timeout_err()), content_type="text/event-stream; charset=utf-8")

    except Exception as e:
        def general_err():
            yield ("data: " + jdump({"error": f"⚠️ Server error: {str(e)}"}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(general_err()), content_type="text/event-stream; charset=utf-8")

# ==========================
# ANALYZE FILE ROUTE
# ==========================

def extract_pdf_text(file_bytes):
    try:
        import io
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            pages = []
            for i, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if text.strip():
                    pages.append(f"[Page {i+1}]\n{text.strip()}")
            return "\n\n".join(pages) if pages else None
        except ImportError:
            pass
        raw = file_bytes.decode("latin-1", errors="replace")
        chunks = re.findall(r'\((.*?)\)', raw)
        text = " ".join(c for c in chunks if len(c) > 2 and c.isprintable())
        return text[:8000] if len(text) > 50 else None
    except Exception:
        return None


def parse_log_file(content, filename):
    lines = content.splitlines()
    total_lines = len(lines)
    SUSPICIOUS = [
        "error", "fail", "denied", "unauthorized", "forbidden",
        "attack", "inject", "overflow", "exploit", "malware",
        "backdoor", "root", "sudo", "privilege", "brute",
        "invalid user", "authentication failure", "connection refused",
        "segfault", "killed", "timeout", "404", "500", "403", "401",
        "xss", "sql", "traversal", "payload", "shell", "exec",
    ]
    flagged = []
    for i, line in enumerate(lines, 1):
        if any(kw in line.lower() for kw in SUSPICIOUS):
            flagged.append(f"  Line {i}: {line.strip()}")
    sample_lines = lines[:100]
    if len(lines) > 100:
        sample_lines += ["", f"  ... [{total_lines - 100} more lines truncated] ...", ""]
        sample_lines += lines[-20:]
    summary = f"File: {filename}\nTotal lines: {total_lines}\n\n"
    summary += "=== FULL LOG SAMPLE ===\n"
    summary += "\n".join(sample_lines[:120])
    if flagged:
        summary += f"\n\n=== ⚠️ SUSPICIOUS LINES DETECTED ({len(flagged)}) ===\n"
        summary += "\n".join(flagged[:50])
        if len(flagged) > 50:
            summary += f"\n  ... and {len(flagged) - 50} more suspicious lines."
    return summary


def build_analysis_prompt(filename, content_summary, file_type):
    ext = file_type.lower()
    if ext == "pdf":
        context = (
            "This is extracted text from a PDF document. "
            "Analyze it for: sensitive data exposure, embedded links or scripts, "
            "social engineering indicators, phishing content, or policy violations."
        )
    elif ext == "log":
        context = (
            "This is a system/application log file. "
            "Analyze it for: brute force attempts, unauthorized access, injection attacks, "
            "privilege escalation, suspicious IPs or commands, error patterns indicating exploitation."
        )
    else:
        context = (
            "Analyze this text file for: hardcoded credentials, API keys, suspicious commands, "
            "malicious scripts, vulnerabilities, or any cybersecurity concerns."
        )
    return (
        f"{context}\n\n"
        f"File name: {filename}\n\n"
        f"Content:\n{content_summary}"
    )


@app.route("/analyze-file", methods=["POST"])
@limiter.limit("10 per minute; 50 per day")
@login_required
def analyze_file():
    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return jsonify({"reply": "No file uploaded."}), 400

    filename = uploaded_file.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"

    ALLOWED = {"txt", "log", "pdf", "py", "js", "json", "yaml", "yml", "conf", "cfg", "csv", "md", "sh", "bash"}
    if ext not in ALLOWED:
        def unsupported():
            yield ("data: " + jdump({"error": f"⚠️ File type `.{ext}` is not supported. Supported: .txt .log .pdf .py .js .json .yaml .conf .sh"}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(unsupported()), content_type="text/event-stream; charset=utf-8")

    try:
        file_bytes = uploaded_file.read()
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
        if len(file_bytes) > MAX_FILE_SIZE:
            def size_err():
                yield ("data: " + jdump({"error": "⚠️ File too large. Maximum allowed size is 5 MB."}) + "\n\n").encode("utf-8")
            return Response(stream_with_context(size_err()), content_type="text/event-stream; charset=utf-8")
        print(f"FILE: {filename} | EXT: {ext} | SIZE: {len(file_bytes)} bytes")

        # ── Extract content based on type ──
        if ext == "pdf":
            extracted = extract_pdf_text(file_bytes)
            if not extracted:
                def pdf_err():
                    yield ("data: " + jdump({"error": "⚠️ Could not extract text from this PDF. It may be scanned (image-only) or encrypted."}) + "\n\n").encode("utf-8")
                return Response(stream_with_context(pdf_err()), content_type="text/event-stream; charset=utf-8")
            content_summary = extracted[:6000]
            if len(extracted) > 6000:
                content_summary += "\n\n[... content truncated for analysis ...]"

        elif ext == "log":
            try:
                raw = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raw = file_bytes.decode("latin-1", errors="replace")
            content_summary = parse_log_file(raw, filename)

        else:
            try:
                raw = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raw = file_bytes.decode("latin-1", errors="replace")
            content_summary = raw[:6000]
            if len(raw) > 6000:
                content_summary += "\n\n[... file truncated after 6000 characters ...]"

        prompt = build_analysis_prompt(filename, content_summary, ext)

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": GENERATION_CONFIG
        }

        # Add Google Search grounding when the file content suggests real-time
        # info would help (CVE IDs, malware names, known threat actors, etc.)
        if needs_grounding(prompt):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        # ── Stream the Gemini response (with retry on 429/503) ──
        gemini_resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=90)

        def generate():
            for raw_line_bytes in gemini_resp.iter_lines():
                raw_line = raw_line_bytes.decode("utf-8") if isinstance(raw_line_bytes, bytes) else raw_line_bytes
                if not raw_line or not raw_line.startswith("data:"):
                    continue
                json_str = raw_line[5:].strip()
                if json_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(json_str)
                    text_piece = (
                        chunk.get("candidates", [{}])[0]
                             .get("content", {})
                             .get("parts", [{}])[0]
                             .get("text", "")
                    )
                    if text_piece:
                        yield ("data: " + jdump({"token": text_piece}) + "\n\n").encode("utf-8")
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue
            yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")

        return Response(
            stream_with_context(generate()),
            content_type="text/event-stream; charset=utf-8",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    except GeminiRateLimitError:
        def rate_err():
            yield ("data: " + jdump({"error": "⚠️ Gemini rate limit reached after retries. Please wait a minute and try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(rate_err()), content_type="text/event-stream; charset=utf-8")

    except GeminiServiceError as e:
        def svc_err():
            yield ("data: " + jdump({"error": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(svc_err()), content_type="text/event-stream; charset=utf-8")

    except requests.exceptions.Timeout:
        def timeout_err():
            yield ("data: " + jdump({"error": "⚠️ Gemini took too long to respond. Try a smaller file or try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(timeout_err()), content_type="text/event-stream; charset=utf-8")

    except Exception as e:
        print(f"analyze_file error: {e}")
        def general_err():
            yield ("data: " + jdump({"error": f"⚠️ Server error: {str(e)}"}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(general_err()), content_type="text/event-stream; charset=utf-8")


# ==========================
# GENERATE TITLE ROUTE
# ==========================

@app.route("/generate-title", methods=["POST"])
@limiter.limit("30 per minute", override_defaults=True)
@login_required
def generate_title():
    """Generate a short smart title for a conversation from its first user message."""
    first_message = ""  # default before try so the except block can always reference it
    try:
        data = request.get_json()
        first_message = (data.get("message", "") if data else "").strip()
        if not first_message:
            return jsonify({"title": "New conversation"})

        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": (
                    f"Generate a very short title (4-6 words max) for a chat conversation "
                    f"that starts with this message. Reply with ONLY the title, no quotes, no punctuation at the end:\n\n{first_message[:300]}"
                )}]
            }],
            "generationConfig": {"maxOutputTokens": 20, "temperature": 0.4}
        }

        resp = gemini_post(API_URL, payload, timeout=15)
        title = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        title = title.strip('"\'').strip()
        return jsonify({"title": title[:60] if title else "New conversation"})

    except Exception:
        return jsonify({"title": first_message[:42] + ("…" if len(first_message) > 42 else "")})

@app.route("/suggest", methods=["POST"])
@limiter.limit("30 per minute", override_defaults=True)
@login_required
def suggest():

    try:
        data = request.get_json()
        query = sanitize_input(data.get("query", ""))

        if len(query) < 2:
            return jsonify({"suggestions": []})

        prompt = f"""
Generate 5 short cybersecurity questions based on:

"{query}"

Rules:
- Return JSON only
- Maximum 5 suggestions
- One line each
- Cybersecurity topics only

Example:
[
  "What is SQL Injection?",
  "How SQL Injection works?",
  "SQL Injection prevention",
  "Blind SQL Injection explained",
  "OWASP SQL Injection"
]
"""

        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 200
            }
        }

        response = gemini_post(API_URL, payload)

        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text.strip())
        suggestions = json.loads(text)

        return jsonify({
            "suggestions": suggestions
        })

    except Exception:
        return jsonify({
            "suggestions": []
        })
# ==========================
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
