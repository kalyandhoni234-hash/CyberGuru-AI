"""
Chat routes

FIX #8: The /investigate command has been removed from the /chat route.
It now has its own dedicated endpoint: POST /api/investigate.
This decouples the conversational AI route from the investigation pipeline,
making both easier to maintain, rate-limit independently, and test.

FIX #7: New /api/chat/sessions/* endpoints expose server-side chat persistence.
The frontend can now create, list, load, rename, and delete named sessions
backed by PostgreSQL instead of relying solely on LocalStorage.
"""

import json
import logging
import requests
from flask import jsonify, request, Response, stream_with_context

from extensions import app, get_user_id_int, limiter, csrf_protect, login_required, get_user_id, jdump
from config import API_URL, API_URL_STREAM, FLASH_LITE_API_URL, FLASH_LITE_API_URL_STREAM, SYSTEM_INSTRUCTION, GENERATION_CONFIG, GOOGLE_SEARCH_TOOL
from services.gemini_service import gemini_post, build_contents, GeminiRateLimitError, GeminiServiceError
from services.cyberguru_agent import investigate
from services.db_service import (
    create_chat_session,
    get_chat_sessions,
    get_chat_session,
    update_chat_session_title,
    delete_chat_session,
    save_message,
    get_messages,
)
from utils.sanitize import sanitize_input, validate_history
from utils.grounding import needs_grounding
from utils.quiz import sanitize_quiz_topic, build_quiz_prompt

logger = logging.getLogger(__name__)

from services.groq_service import groq_chat, groq_stream, build_groq_messages
from services.skill_profile_service import SkillProfileService


def _get_adaptive_system_prompt(user_message: str = "") -> str:
    """Return the base system instruction augmented with the user's skill profile.

    If no authenticated user is present, falls back to the plain SYSTEM_INSTRUCTION.
    The returned prompt is safe to pass to any model (Gemini, Groq, Lite).
    """
    from extensions import get_user_id_int
    user_id = get_user_id_int()
    if user_id is None:
        return SYSTEM_INSTRUCTION
    try:
        svc = SkillProfileService(user_id)
        return svc.build_adaptive_system_prompt(SYSTEM_INSTRUCTION)
    except Exception:
        logger.debug("Could not build adaptive prompt (profile may not exist yet), using base prompt")
        return SYSTEM_INSTRUCTION


# ── Fallback chains ────────────────────────────────────────────────────────────
# Order to try when a model is rate-limited or fails, keyed by requested model.
_FALLBACK_CHAINS = {
    "gemini": ["gemini", "groq", "lite"],
    "groq":   ["groq", "gemini", "lite"],
    "lite":   ["lite", "gemini", "groq"],
}


def _call_model(model_name: str, history: list, user_message: str) -> str:
    """Call a single model and return the reply text. Raises on failure.

    Uses the adaptive system prompt (skill-profile-aware) when available.
    """
    adaptive_prompt = _get_adaptive_system_prompt(user_message)
    if model_name == "gemini":
        payload = {
            "system_instruction": {"parts": [{"text": adaptive_prompt}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG,
        }
        if needs_grounding(user_message):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]
        resp = gemini_post(API_URL, payload, timeout=30)
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    if model_name == "groq":
        messages = build_groq_messages(adaptive_prompt, history, user_message)
        return groq_chat(messages)

    if model_name == "lite":
        payload = {
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG,
        }
        resp = gemini_post(FLASH_LITE_API_URL, payload, timeout=30)
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    raise ValueError(f"Unknown model: {model_name}")


# ==========================
# CHAT ROUTE (non-streaming fallback)
# ==========================
@app.route("/chat", methods=["POST"])
@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def chat():
    data         = request.get_json(silent=True) or {}
    user_message = sanitize_input(data.get("message", ""))
    history      = validate_history(data.get("history", []))
    session_id   = data.get("session_id")
    model        = data.get("model", "gemini")

    if not user_message:
        return jsonify({"reply": "Please enter a message."}), 400

    # Quiz mode
    if user_message.lower().startswith("/quiz"):
        quiz_topic = user_message[5:].strip()
        if not quiz_topic:
            return jsonify({"reply": "⚠️ Please provide a topic.\n\nExample:\n/quiz sql injection"})
        safe_topic = sanitize_quiz_topic(quiz_topic)
        if not safe_topic:
            return jsonify({"reply": (
                "⚠️ That topic isn't in the quiz library.\n\n"
                "Try one of: SQL Injection, XSS, Malware, Phishing, "
                "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                "Buffer Overflow, Social Engineering, or another cybersecurity topic."
            )})
        user_message = build_quiz_prompt(safe_topic)

    # ── Auto-fallback: try each model in the chain ─────────────────
    fallback_chain = _FALLBACK_CHAINS.get(model, _FALLBACK_CHAINS["gemini"])
    fallback_from = []
    last_exc = None

    for m in fallback_chain:
        try:
            bot_reply = _call_model(m, history, user_message)
            _persist_turn(session_id, data.get("message", ""), bot_reply)

            resp = {"reply": bot_reply, "model": m}
            if fallback_from:
                resp["fallback"] = True
                resp["fallback_from"] = fallback_from
            return jsonify(resp)

        except GeminiRateLimitError:
            fallback_from.append(m)
            last_exc = None
            logger.info("Model %s rate limited, trying next in chain", m)
            continue
        except Exception as e:
            fallback_from.append(m)
            last_exc = e
            logger.warning("Model %s failed (%s), trying next in chain", m, type(e).__name__)
            continue

    # All models exhausted
    if last_exc is None:
        return jsonify({"reply": "⚠️ All AI models are rate limited. Please wait a moment and try again."}), 429
    if isinstance(last_exc, requests.exceptions.Timeout):
        return jsonify({"reply": "⚠️ Request timed out on all models."}), 500
    if isinstance(last_exc, requests.exceptions.RequestException):
        return jsonify({"reply": "⚠️ Unable to reach any AI API."}), 500
    logger.exception("All models failed in /chat")
    return jsonify({"reply": "⚠️ All AI models failed. Please try again."}), 500


# ==========================
# CHAT ROUTE (streaming with auto-fallback)
# ==========================

@app.route("/chat-stream", methods=["POST"])
@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def chat_stream():
    try:
        data         = request.get_json(silent=True) or {}
        user_message = sanitize_input(data.get("message", ""))
        history      = validate_history(data.get("history", []))
        session_id   = data.get("session_id")
        model        = data.get("model", "gemini")

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        # Quiz mode
        if user_message.lower().startswith("/quiz"):
            quiz_topic = user_message[5:].strip()
            if not quiz_topic:
                return jsonify({"reply": "⚠️ Please provide a topic.\n\nExample:\n/quiz sql injection"})
            safe_topic = sanitize_quiz_topic(quiz_topic)
            if not safe_topic:
                return jsonify({"reply": (
                    "⚠️ That topic isn't in the quiz library.\n\n"
                    "Try one of: SQL Injection, XSS, Malware, Phishing, "
                    "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                    "Buffer Overflow, Social Engineering, or another cybersecurity topic."
                )})
            user_message = build_quiz_prompt(safe_topic)

        # ── Single streaming generator with fallback chain ─────────
        adaptive_prompt = _get_adaptive_system_prompt(user_message)

        def _stream_gemini_tokens():
            """Yield text tokens from Gemini 2.5 Flash."""
            payload = {
                "system_instruction": {"parts": [{"text": adaptive_prompt}]},
                "contents": build_contents(history, user_message),
                "generationConfig": GENERATION_CONFIG,
            }
            if needs_grounding(user_message):
                payload["tools"] = [GOOGLE_SEARCH_TOOL]
            resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=30)
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

        def _stream_lite_tokens():
            """Yield text tokens from Gemini 3.1 Flash Lite."""
            payload = {
                "contents": build_contents(history, user_message),
                "generationConfig": GENERATION_CONFIG,
            }
            resp = gemini_post(FLASH_LITE_API_URL_STREAM, payload, stream=True, timeout=30)
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

        def generate_with_fallback():
            fallback_chain = _FALLBACK_CHAINS.get(model, _FALLBACK_CHAINS["gemini"])
            last_was_rate_limit = False

            for i, m in enumerate(fallback_chain):
                if i > 0:
                    yield f"data: {jdump({'model_switch': m})}\n\n"

                bot_reply_parts = []
                try:
                    if m == "groq":
                        messages = build_groq_messages(adaptive_prompt, history, user_message)
                        for chunk in groq_stream(messages):
                            bot_reply_parts.append(chunk)
                            yield f"data: {jdump({'token': chunk})}\n\n"
                    elif m == "lite":
                        for token in _stream_lite_tokens():
                            bot_reply_parts.append(token)
                            yield f"data: {jdump({'token': token})}\n\n"
                    else:  # gemini
                        for token in _stream_gemini_tokens():
                            bot_reply_parts.append(token)
                            yield f"data: {jdump({'token': token})}\n\n"

                    yield f"data: {jdump({'done': True})}\n\n"
                    _persist_turn(session_id, data.get("message", ""), "".join(bot_reply_parts))
                    return

                except GeminiRateLimitError:
                    last_was_rate_limit = True
                    logger.info("Stream model %s rate limited, trying next", m)
                    continue
                except GeminiServiceError:
                    last_was_rate_limit = False
                    logger.info("Stream model %s service error, trying next", m)
                    continue
                except Exception:
                    last_was_rate_limit = False
                    logger.warning("Stream model %s failed, trying next", m)
                    continue

            # All models exhausted
            if last_was_rate_limit:
                yield f"data: {jdump({'rate_limited': True, 'retry_after': 60})}\n\n"
            else:
                yield f"data: {jdump({'error': '⚠️ All AI models failed. Please try again.'})}\n\n"

        return Response(stream_with_context(generate_with_fallback()), mimetype="text/event-stream")

    except Exception:
        logger.exception("Unhandled error in /chat-stream")
        return jsonify({"reply": "⚠️ An internal error occurred. Please try again."}), 500


# ==========================
# FIX #8 — /investigate is now its own dedicated endpoint
# ==========================

@app.route("/api/investigate", methods=["POST"])
@limiter.limit("10 per minute; 50 per day", key_func=get_user_id)
@csrf_protect
@login_required
def api_investigate():
    """
    Dedicated investigation endpoint — decoupled from the chat route.
    Previously triggered by a /investigate slash-command inside /chat;
    now a proper REST endpoint with its own stricter rate limit.

    Request:  { "artifact": "<log / email / URL / etc.>" }
    Response: { "report": "...", "investigation": { verdict, severity, mitre, from_cache } }
    """
    try:
        data     = request.get_json(silent=True) or {}
        artifact = sanitize_input(data.get("artifact", ""))

        if not artifact:
            return jsonify({
                "reply": (
                    "⚠️ Please provide an artifact to investigate.\n\n"
                    "Example: send a log snippet, email body, suspicious URL, or IP address."
                )
            }), 400

        result   = investigate(artifact, user_id=get_user_id_int())
        analysis = result.get("analysis", {})

        verdict  = analysis.get("verdict",  "unknown") if analysis.get("status") != "error" else "unknown"
        severity = analysis.get("severity", "unknown") if analysis.get("status") != "error" else "unknown"

        return jsonify({
            "report": result["report"],
            "investigation": {
                "verdict":    verdict,
                "severity":   severity,
                "mitre":      result.get("mitre"),
                "from_cache": result.get("from_cache", False),
            },
        })

    except Exception:
        logger.exception("Unhandled error in /api/investigate")
        return jsonify({"reply": "⚠️ An internal error occurred during investigation. Please try again."}), 500


# ==========================
# FIX #7 — Persistent chat session endpoints
# ==========================

@app.route("/api/chat/sessions", methods=["GET"])
@limiter.limit("60 per minute", key_func=get_user_id)
@login_required
def list_sessions():
    """Return the authenticated user's chat sessions (title + timestamps)."""
    try:
        user_id  = get_user_id_int()
        sessions = get_chat_sessions(user_id)
        return jsonify({"sessions": [dict(s) for s in sessions]})
    except Exception:
        logger.exception("Error listing chat sessions")
        return jsonify({"error": "Could not load sessions."}), 500


@app.route("/api/chat/sessions", methods=["POST"])
@limiter.limit("30 per minute", key_func=get_user_id)
@csrf_protect
@login_required
def new_session():
    """Create a new chat session. Optionally accepts { "title": "..." }."""
    try:
        data    = request.get_json(silent=True) or {}
        title   = sanitize_input(data.get("title", "New conversation"))[:120] or "New conversation"
        user_id = get_user_id_int()
        session = create_chat_session(user_id, title)
        return jsonify({"session": dict(session)}), 201
    except Exception:
        logger.exception("Error creating chat session")
        return jsonify({"error": "Could not create session."}), 500


@app.route("/api/chat/sessions/<int:session_id>", methods=["GET"])
@limiter.limit("60 per minute", key_func=get_user_id)
@login_required
def get_session(session_id):
    """Return a session's metadata + all its messages."""
    try:
        user_id  = get_user_id_int()
        session  = get_chat_session(session_id, user_id)
        if not session:
            return jsonify({"error": "Session not found."}), 404
        messages = get_messages(session_id, user_id)
        return jsonify({
            "session":  dict(session),
            "messages": [dict(m) for m in messages],
        })
    except Exception:
        logger.exception("Error fetching chat session %s", session_id)
        return jsonify({"error": "Could not load session."}), 500


@app.route("/api/chat/sessions/<int:session_id>", methods=["PATCH"])
@limiter.limit("30 per minute", key_func=get_user_id)
@csrf_protect
@login_required
def rename_session(session_id):
    """Rename a session. Body: { "title": "New title" }"""
    try:
        data    = request.get_json(silent=True) or {}
        title   = sanitize_input(data.get("title", "")).strip()
        if not title:
            return jsonify({"error": "title is required"}), 400
        user_id = get_user_id_int()
        updated = update_chat_session_title(session_id, user_id, title)
        if not updated:
            return jsonify({"error": "Session not found."}), 404
        return jsonify({"session": dict(updated)})
    except Exception:
        logger.exception("Error renaming chat session %s", session_id)
        return jsonify({"error": "Could not rename session."}), 500


@app.route("/api/chat/sessions/<int:session_id>", methods=["DELETE"])
@limiter.limit("30 per minute", key_func=get_user_id)
@csrf_protect
@login_required
def delete_session(session_id):
    """Delete a session and all its messages."""
    try:
        user_id = get_user_id_int()
        deleted = delete_chat_session(session_id, user_id)
        if not deleted:
            return jsonify({"error": "Session not found."}), 404
        return jsonify({"ok": True})
    except Exception:
        logger.exception("Error deleting chat session %s", session_id)
        return jsonify({"error": "Could not delete session."}), 500


# ==========================
# Internal helper
# ==========================

def _persist_turn(session_id, user_text: str, bot_text: str):
    """
    If a session_id was provided, persist the user→bot exchange to the DB.
    Errors here are non-fatal — we log and continue.
    """
    if not session_id:
        return
    user_id = get_user_id_int()
    if not user_id:
        return
    try:
        user_saved = save_message(session_id, user_id, "user", user_text)
        bot_saved = save_message(session_id, user_id, "bot", bot_text)
        if not user_saved or not bot_saved:
            logger.warning("Skipped persistence for session %s not owned by user %s", session_id, user_id)
    except Exception:
        logger.exception("Failed to persist turn to session %s", session_id)