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

# Reject any request body over 6MB before Flask buffers it into memory.
# Set slightly above the 5MB file-upload cap enforced in routes/analyze.py
# so legitimate uploads still pass; this stops oversized JSON/multipart
# bodies from being fully read into memory before our own size checks run.
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024

_secret_key = os.getenv("FLASK_SECRET_KEY")
if not _secret_key:
    raise ValueError(
        "FLASK_SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key

# ── Session cookie config ──────────────────────────────────────
# FIX #1: os.getenv returns a string or None, never a bool.
# bool("false") == True in Python, so we must check for None explicitly.
#
# Prefer an explicit APP_ENV var (portable across any host) over detecting
# Render specifically. Falls back to the RENDER auto-set var so the current
# Render deployment keeps working as-is even before APP_ENV is configured
# there — but if this app is ever redeployed elsewhere (Railway, Fly.io, a
# VPS) without setting APP_ENV=production, it would otherwise silently lose
# the Secure cookie flag.
_APP_ENV = os.getenv("APP_ENV", "").strip().lower()
if _APP_ENV:
    IS_PRODUCTION = _APP_ENV == "production"
else:
    IS_PRODUCTION = os.getenv("RENDER") is not None   # Render sets RENDER="true" automatically

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,           # bool, not a string
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,  # 30 days
)

# ── CORS ──────────────────────────────────────────────────────
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS",
    "https://cyberguru-ai.onrender.com"
).split(",") if o.strip()]
CORS(app, origins=_ALLOWED_ORIGINS, supports_credentials=True)

# ── Rate limiter ──────────────────────────────────────────────
# NOTE: In-memory storage means rate limits are NOT shared across multiple
# worker processes. For true multi-process rate limiting on Render, set
# REDIS_URL and switch storage_uri to _REDIS_URL below.
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


@app.errorhandler(413)
def request_too_large_handler(e):
    return jsonify({
        "error": "⚠️ Request body too large. Please reduce the file/content size and try again.",
        "too_large": True
    }), 413


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # F-05: HSTS — only sent over HTTPS in production; prevents downgrade attacks
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "connect-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "media-src 'self' blob: data:;"
        )
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

# F-10: Guard — fail loudly at startup if OAuth credentials are missing
# rather than silently passing None to authlib and crashing at runtime.
_google_client_id     = os.getenv("GOOGLE_CLIENT_ID")
_google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
if not _google_client_id or not _google_client_secret:
    raise ValueError(
        "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set. "
        "Add them to your Render dashboard (or .env for local dev)."
    )

google = oauth.register(
    name="google",
    client_id=_google_client_id,
    client_secret=_google_client_secret,
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


def get_user_id_int():
    """Return the numeric user ID (for database operations). Returns None if not authenticated."""
    user = session.get("user")
    if user and user.get("id"):
        return user["id"]
    return None


def jdump(obj):
    """Serialize with Unicode intact (fixes emoji encoding in SSE streams)."""
    return json.dumps(obj, ensure_ascii=False)