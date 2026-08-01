import json
import logging
from flask import jsonify, request, send_from_directory

from extensions import app, limiter


@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    return jsonify({"status": "ok"}), 200


@app.route('/csp-report', methods=['POST'])
@limiter.limit("30 per minute")
def csp_report():
    """Receives browser CSP violation reports (report-uri directive).

    Logged only — not persisted to the DB. Lets a misconfigured or
    tampered-with CSP surface in application logs instead of failing silently.
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}
    logging.getLogger("csp").warning("CSP violation: %s", json.dumps(payload)[:2000])
    return "", 204


@app.route("/favicon.ico")
@limiter.exempt
def favicon():
    """Some browsers/bookmark tools request /favicon.ico directly,
    bypassing the <link rel="icon"> tag in our templates."""
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")
