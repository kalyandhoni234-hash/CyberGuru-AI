import json
import logging
import requests
from flask import jsonify, request, Response, stream_with_context
from extensions import app, limiter, csrf_protect, login_required, get_user_id, jdump
from config import API_URL_STREAM, SYSTEM_INSTRUCTION, GENERATION_CONFIG, GOOGLE_SEARCH_TOOL
from services.gemini_service import gemini_post, GeminiRateLimitError, GeminiServiceError
from services.file_service import extract_pdf_text, parse_log_file, build_analysis_prompt
from utils.grounding import needs_grounding

logger = logging.getLogger(__name__)
MAGIC_BYTES = {
    b'\x25\x50\x44\x46': 'pdf',
    b'\x50\x4b\x03\x04': 'zip',    # block zip/docx/xlsx disguised as other types
    b'\xff\xd8\xff':      'jpg',    # block image uploads
    b'\x89\x50\x4e\x47': 'png',    # block image uploads
    b'\x47\x49\x46\x38': 'gif',    # block image uploads
    b'\x4d\x5a':          'exe',    # block PE executables
    b'\x7f\x45\x4c\x46': 'elf',    # block ELF binaries (Linux executables)
    b'\xca\xfe\xba\xbe': 'class',  # block Java class files
    b'\x1f\x8b':          'gzip',  # block gzip archives
    b'\x52\x61\x72\x21': 'rar',    # block RAR archives
}

# Types that are never allowed regardless of declared extension
_BLOCKED_MAGIC = {'zip', 'exe', 'elf', 'class', 'gzip', 'rar', 'jpg', 'png', 'gif'}

# Allowed magic types mapped to the extensions they may appear as
_MAGIC_EXTENSION_MAP = {
    'pdf': {'pdf'},
    # text/script files have no magic bytes — they fall through to None
}

def get_magic_type(data: bytes) -> str | None:
    for sig, ftype in MAGIC_BYTES.items():
        if data[:len(sig)] == sig:
            return ftype
    return None

@app.route("/analyze-file", methods=["POST"])
@limiter.limit("10 per minute; 50 per day", key_func=get_user_id)
@csrf_protect
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

        magic = get_magic_type(file_bytes)

        # Block any file whose magic bytes identify it as a dangerous type
        if magic in _BLOCKED_MAGIC:
            def blocked():
                yield ("data: " + jdump({"error": f"⚠️ Blocked: '{magic}' files are not allowed."}) + "\n\n").encode("utf-8")
            return Response(stream_with_context(blocked()), content_type="text/event-stream; charset=utf-8")

        # Block content/extension mismatch — e.g. a PE executable renamed to .txt
        # If magic says it's a pdf, the extension must also be pdf.
        if magic in _MAGIC_EXTENSION_MAP and ext not in _MAGIC_EXTENSION_MAP[magic]:
            def mismatch():
                yield ("data: " + jdump({"error": f"⚠️ File content does not match its extension (.{ext}). Upload rejected."}) + "\n\n").encode("utf-8")
            return Response(stream_with_context(mismatch()), content_type="text/event-stream; charset=utf-8")

        # If extension says pdf but magic bytes disagree, reject it
        if ext == 'pdf' and magic != 'pdf':
            def fake_pdf():
                yield ("data: " + jdump({"error": "⚠️ File does not appear to be a valid PDF."}) + "\n\n").encode("utf-8")
            return Response(stream_with_context(fake_pdf()), content_type="text/event-stream; charset=utf-8")

        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
        if len(file_bytes) > MAX_FILE_SIZE:
            def size_err():
                yield ("data: " + jdump({"error": "⚠️ File too large. Maximum allowed size is 5 MB."}) + "\n\n").encode("utf-8")
            return Response(stream_with_context(size_err()), content_type="text/event-stream; charset=utf-8")
        logger.info("File upload: %s | ext=%s | size=%d bytes", filename, ext, len(file_bytes))

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

        if needs_grounding(prompt):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

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
        status_code = e.status_code  # capture before the implicit `del e` at except-block exit —
                                      # the generator below runs later, after e is gone (see Bug #2 fix)
        def svc_err():
            yield ("data: " + jdump({"error": f"⚠️ Gemini service error ({status_code}). Please try again shortly."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(svc_err()), content_type="text/event-stream; charset=utf-8")

    except requests.exceptions.Timeout:
        def timeout_err():
            yield ("data: " + jdump({"error": "⚠️ Gemini took too long to respond. Try a smaller file or try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(timeout_err()), content_type="text/event-stream; charset=utf-8")

    except Exception as e:
        logger.exception("analyze_file error: %s", e)
        def general_err():
            yield ("data: " + jdump({"error": "⚠️ An internal server error occurred. Please try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(general_err()), content_type="text/event-stream; charset=utf-8")