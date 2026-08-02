import json
import logging
import requests
from flask import jsonify, request, Response, stream_with_context
from extensions import app, limiter, csrf_protect, login_required, get_user_id, get_user_id_int, jdump
from config import API_URL_STREAM, SYSTEM_INSTRUCTION, GENERATION_CONFIG, GOOGLE_SEARCH_TOOL, MAX_INPUT_CHARS
from services.gemini_service import gemini_post, GeminiRateLimitError, GeminiServiceError
from services.db_service import get_investigation_by_id
from services.file_service import extract_pdf_text, parse_log_file, build_analysis_prompt
from utils.grounding import needs_grounding
from utils.sanitize import sanitize_input
from utils.evidence import build_evidence, format_evidence_block

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
@login_required
@csrf_protect
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


# ==========================
# INVESTIGATION-SCOPED AI COPILOT
# ==========================

COPILOT_SYSTEM_INSTRUCTION = """
You are the AI copilot inside the CyberGuru AI Investigation Center, assisting a SOC
analyst who has just run an investigation on a piece of evidence.

## SCOPE
- Answer questions strictly about the artifact under investigation, its extracted
  Indicators of Compromise, the threat-intelligence lookups, the MITRE ATT&CK
  mapping, and the generated incident report.
- The analyst may ask for explanations, remediation steps, detection/sigma guidance,
  likely attack-chains, or clarifications about a verdict.
- Stay grounded in the provided investigation context. If the answer is not
  contained in the context, say so plainly rather than guessing.

## CITATIONS
- The investigation context includes an EVIDENCE REGISTRY with IDs such as E-01,
  E-02, ... one per threat-intel lookup, MITRE technique or IOC.
- Every factual claim you make MUST cite the evidence it rests on by appending the
  E-ID in brackets, e.g. "the IP is 91% abusive per AbuseIPDB [E-01]".
- Do not invent E-IDs that are not in the registry, and do not cite an E-ID unless
  the claim actually follows from that entry.

## ETHICS
- Never encourage illegal hacking, unauthorized access, or malware deployment.
  Frame offensive topics around defense, detection, and authorized use.

## RESPONSE STYLE
- Be concise and practical. Use numbered lists or short headings where they help.
- No long walls of text. Match depth to the question.
"""


def _stream_sse_tokens(resp):
    """Yield SSE `data:` events from a streaming Gemini response."""
    for raw_line in resp.iter_lines():
        if not raw_line:
            continue
        line = raw_line.decode("utf-8")
        if not line.startswith("data:"):
            continue
        json_str = line[5:].strip()
        if not json_str or json_str == "[DONE]":
            continue
        try:
            chunk_data = json.loads(json_str)
            token = (
                chunk_data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )
            if token:
                yield token
        except (json.JSONDecodeError, IndexError, KeyError):
            continue


def _build_copilot_context(row) -> str:
    """Assemble a grounded context block for the copilot from a saved investigation."""
    iocs = row.get("iocs") or {}
    ioc_lines = []
    for key in ("ips", "domains", "urls", "hashes", "emails"):
        for item in iocs.get(key, []):
            ioc_lines.append(f"- {key}: {item}")

    mitre = ""
    if row.get("mitre_id"):
        mitre = f"{row['mitre_id']} - {row.get('mitre_name', 'Unknown')}"

    mitre_techniques = [{"id": row["mitre_id"], "name": row.get("mitre_name")}] if row.get("mitre_id") else []
    evidence = build_evidence(
        iocs=iocs,
        threat_intel=row.get("threat_intel") or {},
        mitre_techniques=mitre_techniques,
    )

    return f"""INVESTIGATION CONTEXT
---------------------
Verdict: {row.get("verdict", "inconclusive")}
Severity: {row.get("severity", "low")}
Confidence: {row.get("confidence") or 0}/100 (evidence-based)
MITRE ATT&CK: {mitre or "None identified"}

{format_evidence_block(evidence)}

EXTRACTED INDICATORS
--------------------
{chr(10).join(ioc_lines) if ioc_lines else "None"}

ORIGINAL ARTIFACT
-----------------
{(row.get("artifact_text") or "")[:8000]}

INCIDENT REPORT
---------------
{(row.get("report") or "")[:8000]}
"""


@app.route("/api/investigate/ask", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@login_required
@csrf_protect
def investigate_ask():
    """Investigation-scoped copilot: answer a follow-up question grounded in a
    previously run investigation.

    Request:  { "investigation_id": <int>, "question": "<text>" }
    Response: SSE stream of `data:` token events, ending with a `done` event.
    """
    try:
        data = request.get_json(silent=True) or {}
        question = sanitize_input(data.get("question", ""))[:MAX_INPUT_CHARS].strip()
        investigation_id = data.get("investigation_id")

        if not question:
            return jsonify({"error": "Please enter a question."}), 400

        try:
            investigation_id = int(investigation_id)
        except (TypeError, ValueError):
            return jsonify({"error": "investigation_id must be an integer."}), 400

        user_id = get_user_id_int()
        row = get_investigation_by_id(investigation_id, user_id)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404

        context = _build_copilot_context(row)
        user_prompt = (
            f"{context}\n\n"
            f"ANALYST QUESTION\n"
            f"----------------\n{question}\n\n"
            f"Answer the analyst's question using the investigation context above."
        )

        payload = {
            "system_instruction": {"parts": [{"text": COPILOT_SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": GENERATION_CONFIG,
        }

        gemini_resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=60)

        def generate():
            try:
                for token in _stream_sse_tokens(gemini_resp):
                    yield ("data: " + jdump({"token": token}) + "\n\n").encode("utf-8")
                yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")
            except GeminiRateLimitError:
                yield ("data: " + jdump({"error": "⚠️ Gemini rate limit reached. Please wait a minute and try again."}) + "\n\n").encode("utf-8")
            except GeminiServiceError as e:
                status_code = e.status_code
                yield ("data: " + jdump({"error": f"⚠️ Gemini service error ({status_code}). Please try again shortly."}) + "\n\n").encode("utf-8")
            except requests.exceptions.Timeout:
                yield ("data: " + jdump({"error": "⚠️ Gemini took too long to respond. Please try again."}) + "\n\n").encode("utf-8")
            except Exception:
                logger.exception("Copilot streaming failed")
                yield ("data: " + jdump({"error": "⚠️ An internal error occurred. Please try again."}) + "\n\n").encode("utf-8")

        return Response(
            stream_with_context(generate()),
            content_type="text/event-stream; charset=utf-8",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    except Exception:
        logger.exception("Unhandled error in /api/investigate/ask")
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500