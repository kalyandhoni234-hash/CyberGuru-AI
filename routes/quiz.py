"""
routes/quiz.py
────────────────
Interactive Quiz Mode routes.

Wires services/quiz_service.py (Groq-powered) into the app.

Flow:
  1. GET  /api/quiz/start    → generate a quiz, stash the answer key
                                server-side, return the safe-to-show
                                parts to the client (no correct answers).
  2. POST /api/quiz/submit   → grade the player's answers against the
                                stashed quiz locally, return the result,
                                then clear the stash.

The full quiz (including the "correct" letter and "explanation" per
question) is NEVER sent to the browser on step 1 — only after grading,
so the answer key can't be read out of the network tab mid-quiz.
"""

import logging
from flask import jsonify, request

from extensions import app, limiter, csrf_protect, login_required, get_user_id, get_user_id_int
from services.quiz_service import get_quiz, grade_quiz, QUIZ_TOPICS
from utils.cache import get_cached, set_cached

logger = logging.getLogger(__name__)

QUIZ_CACHE_PREFIX = "quiz_active"
QUIZ_TTL_SECONDS = 30 * 60  # 30 minutes to finish a quiz


def _public_quiz(quiz: dict) -> dict:
    """Strip the answer key + explanations so they never reach the browser pre-grading."""
    return {
        "topic": quiz.get("topic"),
        "title": quiz.get("title"),
        "generated_at": quiz.get("generated_at"),
        "questions": [
            {
                "id": q.get("id"),
                "question": q.get("question"),
                "options": q.get("options"),
            }
            for q in quiz.get("questions", [])
        ],
    }


@app.route("/api/quiz/start", methods=["GET"])
@limiter.limit("10 per minute; 60 per day", key_func=get_user_id)
@login_required
def quiz_start():
    """
    Generate (or refresh) the player's active quiz.

    Query params:
        topic   optional, one of QUIZ_TOPICS. Defaults to a random topic.
        new     optional "1" — force a brand-new quiz even if one is
                already active for this user.
    """
    try:
        user_id = get_user_id_int()
        topic = request.args.get("topic")
        force_new = request.args.get("new") == "1"

        if not force_new:
            cached = get_cached(QUIZ_CACHE_PREFIX, str(user_id))
            if cached:
                return jsonify({
                    "status": "ok",
                    "quiz": _public_quiz(cached),
                    "from_cache": True,
                }), 200

        result = get_quiz(topic)

        if not result.get("ok"):
            status = 429 if result.get("rate_limited") else 502
            return jsonify({
                "status": "error",
                "message": result.get("error", "Could not generate a quiz right now."),
            }), status

        quiz = result["quiz"]
        set_cached(QUIZ_CACHE_PREFIX, str(user_id), quiz, QUIZ_TTL_SECONDS)

        return jsonify({
            "status": "ok",
            "quiz": _public_quiz(quiz),
            "from_cache": False,
        }), 200

    except Exception:
        logger.exception("Unhandled error in /api/quiz/start")
        return jsonify({"status": "error", "message": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/quiz/submit", methods=["POST"])
@limiter.limit("15 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def quiz_submit():
    """
    Grade the player's answers against their active quiz.

    Request body:
        { "answers": { "q1": "A", "q2": "C", ... } }
    """
    try:
        user_id = get_user_id_int()
        data = request.get_json(silent=True) or {}
        answers = data.get("answers")

        if not isinstance(answers, dict) or not answers:
            return jsonify({"status": "error", "message": "Please answer at least one question before submitting."}), 400

        quiz = get_cached(QUIZ_CACHE_PREFIX, str(user_id))
        if not quiz:
            return jsonify({
                "status": "error",
                "message": "No active quiz found (it may have expired). Start a new one first.",
                "expired": True,
            }), 400

        result = grade_quiz(quiz, answers)

        # Quiz is consumed once graded so the same answers can't be resubmitted.
        set_cached(QUIZ_CACHE_PREFIX, str(user_id), None, 1)

        return jsonify({
            "status": "ok",
            "result": result["result"],
            "quiz_title": quiz.get("title"),
            "quiz_topic": quiz.get("topic"),
        }), 200

    except Exception:
        logger.exception("Unhandled error in /api/quiz/submit")
        return jsonify({"status": "error", "message": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/quiz/info", methods=["GET"])
def quiz_info():
    """Public metadata about Quiz Mode (no auth required)."""
    return jsonify({
        "name": "CyberGuru Quiz Mode",
        "description": "AI-generated multiple-choice cybersecurity quizzes, graded instantly on submission.",
        "topics": QUIZ_TOPICS,
        "questions_per_quiz": 5,
        "status": "ready",
        "endpoints": [
            {"method": "GET", "path": "/api/quiz/start", "description": "Get/generate active quiz", "requires_auth": True},
            {"method": "POST", "path": "/api/quiz/submit", "description": "Submit and grade answers", "requires_auth": True},
        ],
        "rate_limits": {
            "start": "10 per minute, 60 per day",
            "submit": "15 per minute, 100 per day",
        },
    }), 200
