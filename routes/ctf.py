"""
routes/ctf.py
──────────────
CTF / Challenge Mode routes.

Wires services/ctf_service.py (Groq-powered) into the app.

Flow:
  1. GET  /api/ctf/challenge   → generate a challenge, stash the answer
                                  key server-side, return the safe-to-show
                                  parts to the client.
  2. POST /api/ctf/submit      → grade the user's answer against the
                                  stashed challenge, return the result,
                                  then clear the stash.

The full challenge (including correct_answer / key_indicators) is NEVER
sent to the browser on step 1 — only after scoring, as part of the
"reveal". This prevents reading the answer out of the network tab.
"""

import logging
from flask import jsonify, request

from extensions import app, limiter, csrf_protect, login_required, get_user_id, get_user_id_int
from services.ctf_service import get_ctf_challenge, score_ctf_answer, CTF_CATEGORIES
from utils.cache import get_cached, set_cached

logger = logging.getLogger(__name__)

CTF_CACHE_PREFIX = "ctf_active"
CTF_CHALLENGE_TTL_SECONDS = 60 * 60  # 1 hour to solve a challenge


def _public_challenge(challenge: dict) -> dict:
    """Strip the answer key so it never reaches the browser pre-scoring."""
    return {
        "category": challenge.get("category"),
        "title": challenge.get("title"),
        "difficulty": challenge.get("difficulty"),
        "scenario": challenge.get("scenario"),
        "artifact": challenge.get("artifact"),
        "question": challenge.get("question"),
        "hints": challenge.get("hints", []),
        "generated_at": challenge.get("generated_at"),
    }


@app.route("/api/ctf/challenge", methods=["GET"])
@limiter.limit("10 per minute; 60 per day", key_func=get_user_id)
@login_required
def ctf_challenge():
    """
    Generate (or refresh) the player's active CTF challenge.

    Query params:
        category   optional, one of CTF_CATEGORIES. Defaults to this
                   week's rotating category.
        new        optional "1" — force a brand-new challenge even if
                   one is already active for this user.
    """
    try:
        user_id = get_user_id_int()
        category = request.args.get("category")
        force_new = request.args.get("new") == "1"

        if not force_new:
            cached = get_cached(CTF_CACHE_PREFIX, str(user_id))
            if cached:
                return jsonify({
                    "status": "ok",
                    "challenge": _public_challenge(cached),
                    "from_cache": True,
                }), 200

        result = get_ctf_challenge(category)

        if not result.get("ok"):
            status = 429 if result.get("rate_limited") else 502
            return jsonify({
                "status": "error",
                "message": result.get("error", "Could not generate a challenge right now."),
            }), status

        challenge = result["challenge"]
        set_cached(CTF_CACHE_PREFIX, str(user_id), challenge, CTF_CHALLENGE_TTL_SECONDS)

        return jsonify({
            "status": "ok",
            "challenge": _public_challenge(challenge),
            "from_cache": False,
        }), 200

    except Exception:
        logger.exception("Unhandled error in /api/ctf/challenge")
        return jsonify({"status": "error", "message": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/ctf/submit", methods=["POST"])
@limiter.limit("15 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def ctf_submit():
    """
    Score the player's answer against their active challenge.

    Request body:
        { "answer": "the player's written answer" }
    """
    try:
        user_id = get_user_id_int()
        data = request.get_json(silent=True) or {}
        user_answer = (data.get("answer") or "").strip()

        if not user_answer:
            return jsonify({"status": "error", "message": "Please write an answer before submitting."}), 400

        challenge = get_cached(CTF_CACHE_PREFIX, str(user_id))
        if not challenge:
            return jsonify({
                "status": "error",
                "message": "No active challenge found (it may have expired). Request a new one first.",
                "expired": True,
            }), 400

        result = score_ctf_answer(challenge, user_answer)

        if not result.get("ok"):
            status = 429 if result.get("rate_limited") else 502
            return jsonify({
                "status": "error",
                "message": result.get("error", "Could not grade your answer right now."),
            }), status

        # Challenge is consumed once graded so the same answer can't be resubmitted.
        set_cached(CTF_CACHE_PREFIX, str(user_id), None, 1)

        return jsonify({
            "status": "ok",
            "result": result["result"],
            "challenge_title": challenge.get("title"),
            "challenge_category": challenge.get("category"),
        }), 200

    except Exception:
        logger.exception("Unhandled error in /api/ctf/submit")
        return jsonify({"status": "error", "message": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/ctf/info", methods=["GET"])
def ctf_info():
    """Public metadata about CTF mode (no auth required)."""
    return jsonify({
        "name": "CyberGuru CTF Challenge Mode",
        "description": "AI-generated SOC-analyst-style security challenges, scored on submission.",
        "categories": CTF_CATEGORIES,
        "status": "ready",
        "endpoints": [
            {"method": "GET", "path": "/api/ctf/challenge", "description": "Get/generate active challenge", "requires_auth": True},
            {"method": "POST", "path": "/api/ctf/submit", "description": "Submit and score an answer", "requires_auth": True},
        ],
        "rate_limits": {
            "challenge": "10 per minute, 60 per day",
            "submit": "15 per minute, 100 per day",
        },
    }), 200