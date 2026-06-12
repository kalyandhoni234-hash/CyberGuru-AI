import re
import json
from flask import jsonify, render_template, request

from extensions import app, limiter, csrf_protect, login_required, get_user_id
from config import API_URL
from services.gemini_service import gemini_post
from utils.sanitize import sanitize_input


@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate-title", methods=["POST"])
@limiter.limit("30 per minute", override_defaults=True, key_func=get_user_id)
@csrf_protect
@login_required
def generate_title():
    """Generate a short smart title for a conversation from its first user message."""
    first_message = ""
    try:
        data = request.get_json()
        first_message = (data.get("message", "") if data else "").strip()
        if not first_message:
            return jsonify({"title": "New conversation"})

        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": (
                    f"Generate a very short title (4-6 words max) for a chat conversation "
                    f"that starts with this message. Reply with ONLY the title, no quotes, no punctuation at the end:\n\n{first_message[:300]}"
                )}]
            }],
            "generationConfig": {"maxOutputTokens": 20, "temperature": 0.4}
        }

        resp = gemini_post(API_URL, payload, timeout=15)
        title = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        title = title.strip('"\'').strip()
        return jsonify({"title": title[:60] if title else "New conversation"})

    except Exception:
        return jsonify({"title": first_message[:42] + ("…" if len(first_message) > 42 else "")})


@app.route("/suggest", methods=["POST"])
@limiter.limit("30 per minute", override_defaults=True, key_func=get_user_id)
@csrf_protect
@login_required
def suggest():
    try:
        data = request.get_json()
        query = sanitize_input(data.get("query", ""))

        if len(query) < 2:
            return jsonify({"suggestions": []})

        prompt = f"""
Generate 5 short cybersecurity questions based on:

"{query}"

Rules:
- Return JSON only
- Maximum 5 suggestions
- One line each
- Cybersecurity topics only

Example:
[
  "What is SQL Injection?",
  "How SQL Injection works?",
  "SQL Injection prevention",
  "Blind SQL Injection explained",
  "OWASP SQL Injection"
]
"""

        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 200
            }
        }

        response = gemini_post(API_URL, payload)

        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text.strip())
        suggestions = json.loads(text)

        return jsonify({"suggestions": suggestions})

    except Exception:
        return jsonify({"suggestions": []})
