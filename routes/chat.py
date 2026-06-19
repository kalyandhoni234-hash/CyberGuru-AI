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
from config import API_URL, API_URL_STREAM, SYSTEM_INSTRUCTION, GENERATION_CONFIG, GOOGLE_SEARCH_TOOL
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


# ==========================
# CHAT ROUTE (non-streaming fallback)
# ==========================
@app.route("/chat", methods=["POST"])
@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def chat():
    try:
        data         = request.get_json(silent=True) or {}
        user_message = sanitize_input(data.get("message", ""))
        history      = validate_history(data.get("history", []))
        session_id   = data.get("session_id")   # optional — if provided, auto-persist
        model        = data.get("model", "gemini")  # "gemini" | "groq"

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        # Quiz mode
        quiz_mode  = False
        quiz_topic = ""
        if user_message.lower().startswith("/quiz"):
            quiz_mode  = True
            quiz_topic = user_message[5:].strip()

        if quiz_mode:
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

        # ── Groq path ──────────────────────────────────────────────
        if model == "groq":
            messages  = build_groq_messages(SYSTEM_INSTRUCTION, history, user_message)
            bot_reply = groq_chat(messages)
            _persist_turn(session_id, data.get("message", ""), bot_reply)
            return jsonify({"reply": bot_reply, "model": "groq"})

        # ── Gemini path ────────────────────────────────────────────
        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG,
        }

        if needs_grounding(user_message):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        response = gemini_post(API_URL, payload, timeout=30)
        response_data = response.json()
        bot_reply = response_data["candidates"][0]["content"]["parts"][0]["text"]

        # Persist to DB if a session_id was supplied.
        _persist_turn(session_id, data.get("message", ""), bot_reply)

        return jsonify({"reply": bot_reply, "model": "gemini"})

    except GeminiRateLimitError:
        return jsonify({"reply": "⚠️ Gemini rate limit reached. Please wait a moment and try again."}), 429
    except GeminiServiceError as e:
        return jsonify({"reply": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}), 503
    except requests.exceptions.Timeout:
        return jsonify({"reply": "⚠️ Request timed out."}), 500
    except requests.exceptions.RequestException:
        return jsonify({"reply": "⚠️ Unable to reach Gemini API."}), 500
    except KeyError:
        return jsonify({"reply": "⚠️ Unexpected response format from Gemini."}), 500
    except Exception:
        logger.exception("Unhandled error in /chat")
        return jsonify({"reply": "⚠️ An internal error occurred. Please try again."}), 500


# ==========================
# CHAT ROUTE (streaming)
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
        model        = data.get("model", "gemini")  # "gemini" | "groq"

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

        # ── Groq streaming path ────────────────────────────────────
        if model == "groq":
            messages = build_groq_messages(SYSTEM_INSTRUCTION, history, user_message)

            def generate_groq():
                bot_reply_parts = []
                try:
                    for chunk in groq_stream(messages):
                        bot_reply_parts.append(chunk)
                        yield f"data: {jdump({'token': chunk})}\n\n"
                    yield f"data: {jdump({'done': True})}\n\n"
                    _persist_turn(session_id, data.get("message", ""), "".join(bot_reply_parts))
                except Exception:
                    logger.exception("Unhandled error in /chat-stream groq generator")
                    yield f"data: {jdump({'error': '⚠️ Groq error. Please try again.'})}\n\n"

            return Response(stream_with_context(generate_groq()), mimetype="text/event-stream")

        # ── Gemini streaming path ──────────────────────────────────
        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG,
        }

        if needs_grounding(user_message):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        def generate():
            bot_reply_parts = []
            try:
                # gemini_post returns a Response object; iterate its lines for SSE
                resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=30)
                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    # raw_line is bytes, e.g. b'data: {"candidates":[...]}'
                    line = raw_line.decode("utf-8")
                    if not line.startswith("data:"):
                        continue
                    json_str = line[5:].strip()
                    if not json_str or json_str == "[DONE]":
                        continue
                    try:
                        chunk_data = json.loads(json_str)
                        token = (
                            chunk_data
                            .get("candidates", [{}])[0]
                            .get("content", {})
                            .get("parts", [{}])[0]
                            .get("text", "")
                        )
                        if token:
                            bot_reply_parts.append(token)
                            yield f"data: {jdump({'token': token})}\n\n"
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue

                yield f"data: {jdump({'done': True})}\n\n"
                _persist_turn(session_id, data.get("message", ""), "".join(bot_reply_parts))

            except GeminiRateLimitError:
                yield f"data: {jdump({'rate_limited': True, 'retry_after': 60})}\n\n"
            except GeminiServiceError as e:
                yield f"data: {jdump({'error': f'⚠️ Gemini service error ({e.status_code}).'})}\n\n"
            except requests.exceptions.Timeout:
                yield f"data: {jdump({'error': '⚠️ Request timed out.'})}\n\n"
            except requests.exceptions.RequestException:
                yield f"data: {jdump({'error': '⚠️ Unable to reach Gemini API.'})}\n\n"
            except Exception:
                logger.exception("Unhandled error in /chat-stream generator")
                yield f"data: {jdump({'error': '⚠️ An internal error occurred.'})}\n\n"

        return Response(stream_with_context(generate()), mimetype="text/event-stream")

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