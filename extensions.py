"""
Shared extension instances (app, limiter, oauth, csrf helpers).
Created here to avoid circular imports between app.py and routes/*.
"""

import os
import json
import secrets as _secrets
from functools import wraps

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False   # preserve emojis in jsonify() responses

_secret_key = os.getenv("FLASK_SECRET_KEY")
if not _secret_key:
    raise ValueError(
        "FLASK_SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key

# ── Session cookie config ──────────────────────────────────────
IS_PRODUCTION = os.getenv("RENDER", False)  # Render sets this automatically
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(IS_PRODUCTION),
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,  # 30 days
)

# ── CORS ──────────────────────────────────────────────────────
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS",
    "https://cyber-guru-ai.vercel.app"
).split(",") if o.strip()]
CORS(app, origins=_ALLOWED_ORIGINS, supports_credentials=True)

# ── Rate limiter ──────────────────────────────────────────────
_REDIS_URL = os.getenv("REDIS_URL")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri=_REDIS_URL if _REDIS_URL else "memory://",
)


@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({
        "reply": f"⚠️ Too many requests — {e.description}. Please slow down and try again shortly.",
        "rate_limited": True,
        "retry_after": 60
    }), 429


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not response.content_type.startswith("text/html"):
        response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# ==========================
# CSRF PROTECTION (Double-Submit Cookie pattern)
# ==========================

def _get_csrf_token() -> str:
    """Return the current session CSRF token, minting one if absent."""
    if "csrf_token" not in session:
        session["csrf_token"] = _secrets.token_hex(32)
    return session["csrf_token"]


def csrf_protect(f):
    """Decorator: verify X-CSRF-Token header matches the session token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("csrf_token")
        header = request.headers.get("X-CSRF-Token", "")
        if not token or not header or not _secrets.compare_digest(token, header):
            return jsonify({"error": "CSRF validation failed", "csrf_error": True}), 403
        return f(*args, **kwargs)
    return decorated


# ==========================
# AUTH HELPERS
# ==========================

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def login_required(f):
    """Decorator: reject unauthenticated API calls with 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Authentication required", "auth_required": True}), 401
        return f(*args, **kwargs)
    return decorated


def get_user_id():
    """Key function for per-user rate limiting on authenticated routes."""
    user = session.get("user")
    if user:
        return f"user:{user['id']}"
    return get_remote_address()


def jdump(obj):
    """Serialize with Unicode intact (fixes emoji encoding in SSE streams)."""
    return json.dumps(obj, ensure_ascii=False)
