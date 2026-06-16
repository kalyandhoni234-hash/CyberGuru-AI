"""
Cybersecurity Triage Routes

FIX #2: Exception handlers no longer return str(e) to the client.
Internal error details are logged server-side; the response body contains
only a safe, generic message. This prevents stack traces, file paths, and
connection strings from leaking to end users.
"""

import logging
from flask import jsonify, request

from extensions import app, limiter, csrf_protect, login_required, get_user_id
from services.triage_service import (
    analyze_artifact,
    analyze_log,
    analyze_email,
    analyze_malware,
)

logger = logging.getLogger(__name__)


# ==========================
# TRIAGE API ENDPOINTS
# ==========================

@app.route("/api/triage/analyze", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze():
    """
    Analyze a security artifact (auto-detect type or specify).

    Request:
    {
        "artifact": "log content / email / malware report",
        "type": "auto | log | phishing_email | malware | url"
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        artifact = data.get("artifact", "").strip()
        artifact_type = data.get("type", "auto")

        if not artifact:
            return jsonify({"error": "artifact field is required"}), 400

        result = analyze_artifact(artifact, artifact_type)

        if result.get("status") == "error":
            # triage_service already logged the real error; return a safe message.
            return jsonify({
                "status": "error",
                "message": result.get("message", "Analysis failed"),
            }), 500

        return jsonify(result), 200

    except Exception:
        logger.exception("Unhandled error in /api/triage/analyze")
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/triage/analyze-log", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_log():
    """Analyze a log file for security threats."""
    try:
        data = request.get_json(silent=True) or {}
        log_content = data.get("log", "").strip()

        if not log_content:
            return jsonify({"error": "log field is required"}), 400

        result = analyze_log(log_content)

        if result.get("status") == "error":
            return jsonify({
                "status": "error",
                "message": result.get("message", "Log analysis failed"),
            }), 500

        return jsonify(result), 200

    except Exception:
        logger.exception("Unhandled error in /api/triage/analyze-log")
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/triage/analyze-email", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_email():
    """Analyze an email for phishing/security threats."""
    try:
        data = request.get_json(silent=True) or {}
        email_content = data.get("email", "").strip()

        if not email_content:
            return jsonify({"error": "email field is required"}), 400

        result = analyze_email(
            email_content,
            subject=data.get("subject"),
            sender=data.get("from"),
            urls=data.get("urls", []),
        )

        if result.get("status") == "error":
            return jsonify({
                "status": "error",
                "message": result.get("message", "Email analysis failed"),
            }), 500

        return jsonify(result), 200

    except Exception:
        logger.exception("Unhandled error in /api/triage/analyze-email")
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/triage/analyze-malware", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_malware():
    """Analyze a malware behavior report."""
    try:
        data = request.get_json(silent=True) or {}
        report = data.get("report", "").strip()

        if not report:
            return jsonify({"error": "report field is required"}), 400

        result = analyze_malware(report)

        if result.get("status") == "error":
            return jsonify({
                "status": "error",
                "message": result.get("message", "Malware analysis failed"),
            }), 500

        return jsonify(result), 200

    except Exception:
        logger.exception("Unhandled error in /api/triage/analyze-malware")
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500


@app.route("/api/triage/info", methods=["GET"])
def triage_info():
    """Get information about available triage endpoints (no auth required)."""
    return jsonify({
        "name": "Cybersecurity Triage Agent",
        "description": "AI-powered security artifact analysis",
        "status": "ready",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/triage/analyze",
                "description": "Analyze any security artifact (auto-detect type)",
                "requires_auth": True,
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-log",
                "description": "Analyze a log file for threats",
                "requires_auth": True,
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-email",
                "description": "Analyze an email for phishing",
                "requires_auth": True,
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-malware",
                "description": "Analyze malware behavior",
                "requires_auth": True,
            },
        ],
        "rate_limits": {
            "analyze_endpoints": "20 per minute, 100 per day",
        },
    }), 200
