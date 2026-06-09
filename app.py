from dotenv import load_dotenv
import os
import re
import json
import base64
import time
import requests
from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context
from flask_cors import CORS

print("RUNNING FILE:", __file__)
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False   # preserve emojis in jsonify() responses
CORS(app)

# Always serialize JSON with Unicode intact (fixes emoji encoding in SSE streams)
def jdump(obj):
    return json.dumps(obj, ensure_ascii=False)

# ==========================
# CONFIGURATION
# ==========================

load_dotenv()
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
You are CyberGuru AI, an expert cybersecurity mentor.

Rules:

1. Answer only cybersecurity-related questions.

2. For unrelated questions, reply:
"I am CyberGuru AI and can only assist with cybersecurity topics."
 but for general questions like hi,how are you you to reply in soft tone

3. Explain concepts in a beginner-friendly way.

4. Structure answers using:
   - Definition
   - Example
   - Why it matters
   - Prevention/Mitigation

5. Use bullet points when possible.

6. For tools, commands, or code:
   - Explain what each part does.
   - Mention risks if applicable.

7. Never encourage illegal hacking,
   unauthorized access,
   malware deployment,
   credential theft,
   or harmful activities.

8. When discussing offensive security,
   focus on education,
   defense,
   detection,
   and ethical use.

9. Keep responses concise unless the user asks for details.

10. Use emojis occasionally:
🛡️ 🔍 ⚠️ ✅
11. Do not write textbook-style responses.

Avoid excessive headings, emojis, and repetitive structures.

Prioritize concise, practical explanations.

Adapt answer length to the user's question.

For beginner questions:
- Explain simply.
- Give actionable next steps.
- Avoid turning every answer into a complete guide.

Use headings only when they improve readability.
12.If the answer exceeds 500 words, first ask:
"Would you like a detailed explanation?"
unless the user explicitly requests detail.
13. add this line after every response
"──────
🛡️ CyberGuru AI"
14. use chatgpt response style like for headings with points,bullete points, more understandable for 
use number pointers instead of "* "
"""

# Max messages to send as history (keeps token usage reasonable)
MAX_HISTORY_TURNS = 10

# Applied to every Gemini request — prevents cut-off responses
GENERATION_CONFIG = {
    "maxOutputTokens": 8192,
    "temperature": 0.7,
}

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

    for msg in trimmed:
        role = msg.get("role", "")
        text = msg.get("text", "")
        if not role or not isinstance(text, str):
            continue  # skip malformed history entries
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


# ==========================
# HEALTH CHECK
# ==========================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ==========================
# CHAT ROUTE (non-streaming, kept for fallback)
# ==========================

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        user_message = data.get("message", "").strip()
        history      = data.get("history", [])

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

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
def chat_stream():
    try:
        data = request.get_json()
        user_message = data.get("message", "").strip()
        history      = data.get("history", [])

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

        # Open a streaming request to Gemini (with retry on 429/503)
        gemini_resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=60)

        def generate():
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
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
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
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
