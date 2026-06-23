"""
Profile routes — Skill-level personalisation layer.

Endpoints:
  GET   /api/profile              — Return the user's profile + progress.
  POST  /api/profile/onboard      — Complete onboarding (set skill level).
  PATCH /api/profile              — Update skill level.
  GET   /api/prompt-suggestions   — Get dynamic prompt suggestions for a module.
"""

import logging

from flask import jsonify, request
from extensions import app, limiter, csrf_protect, login_required, get_user_id, get_user_id_int
from services.skill_profile_service import SkillProfileService
from services.prompt_suggestion_service import PromptSuggestionService
from utils.sanitize import sanitize_input

logger = logging.getLogger(__name__)

VALID_SKILL_LEVELS = ("beginner", "intermediate", "advanced")
VALID_MODULES = ("chat", "investigate", "mentor", "ctf")


def _get_profile_service() -> SkillProfileService:
    """Helper: instantiate the service for the current authenticated user."""
    user_id = get_user_id_int()
    if not user_id:
        raise RuntimeError("get_user_id_int() returned None on authenticated route — this should not happen")
    return SkillProfileService(user_id)


@app.route("/api/profile", methods=["GET"])
@limiter.limit("60 per minute", key_func=get_user_id)
@login_required
def get_profile():
    """Return the user's profile including progress."""
    try:
        svc = _get_profile_service()
        summary = svc.get_profile_summary()
        return jsonify(summary)
    except Exception:
        logger.exception("Error fetching profile")
        return jsonify({"error": "Could not load profile."}), 500


@app.route("/api/profile/onboard", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_user_id)
@csrf_protect
@login_required
def onboard_profile():
    """Complete the onboarding flow.

    Request body (JSON):
      { "skill_level": "beginner" | "intermediate" | "advanced" }
    """
    try:
        data = request.get_json(silent=True) or {}
        level = sanitize_input((data.get("skill_level") or "").strip().lower())

        if level not in VALID_SKILL_LEVELS:
            return jsonify({"error": f"Invalid skill level. Must be one of: {', '.join(VALID_SKILL_LEVELS)}"}), 400

        svc = _get_profile_service()
        svc.complete_onboarding(level)
        # Auto-set initial topic
        svc.set_current_topic("Getting Started with Cybersecurity")

        summary = svc.get_profile_summary()
        return jsonify({"ok": True, "profile": summary}), 201

    except Exception:
        logger.exception("Error during profile onboarding")
        return jsonify({"error": "Could not complete onboarding."}), 500


@app.route("/api/profile", methods=["PATCH"])
@limiter.limit("30 per minute", key_func=get_user_id)
@csrf_protect
@login_required
def update_profile_route():
    """Update the user's skill level.

    Request body (JSON):
      { "skill_level": "beginner" | "intermediate" | "advanced" }
    """
    try:
        data = request.get_json(silent=True) or {}
        svc = _get_profile_service()

        level = data.get("skill_level")
        if level is not None:
            level = sanitize_input(level).strip().lower()
            if level not in VALID_SKILL_LEVELS:
                return jsonify({"error": f"Invalid skill level. Must be one of: {', '.join(VALID_SKILL_LEVELS)}"}), 400
            svc.set_skill_level(level)
        else:
            return jsonify({"error": "skill_level is required."}), 400

        summary = svc.get_profile_summary()
        return jsonify({"ok": True, "profile": summary})

    except Exception:
        logger.exception("Error updating profile")
        return jsonify({"error": "Could not update profile."}), 500


# ── Prompt Suggestions ────────────────────────────────────────────────────────


@app.route("/api/prompt-suggestions", methods=["GET"])
@limiter.limit("120 per minute", key_func=get_user_id)
@login_required
def get_prompt_suggestions():
    """Return dynamic prompt suggestions for the given module.

    Query params:
      module (str): 'chat', 'investigate', or 'mentor' (default: 'chat').
      count  (int): Number of suggestions (default: 4, max: 8).
    """
    try:
        module = (request.args.get("module") or "chat").strip().lower()
        if module not in VALID_MODULES:
            return jsonify({"error": f"Invalid module. Must be one of: {', '.join(VALID_MODULES)}"}), 400

        try:
            count = max(1, min(8, int(request.args.get("count", 4))))
        except (ValueError, TypeError):
            count = 4

        q = request.args.get("q", "").strip() or None

        user_id = get_user_id_int()
        svc = PromptSuggestionService(user_id)
        suggestions = svc.get_suggestions(module, count, q=q)

        return jsonify({
            "module": module,
            "suggestions": suggestions,
        })

    except Exception:
        logger.exception("Error fetching prompt suggestions")
        return jsonify({"error": "Could not load suggestions."}), 500
