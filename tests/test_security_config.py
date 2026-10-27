"""Security configuration regression tests (no external services)."""

import sys

import extensions


def test_missing_redis_package_falls_back_to_memory(monkeypatch):
    """Setting REDIS_URL must not crash startup when redis is not installed."""
    monkeypatch.setattr(extensions, "_REDIS_URL", "redis://example.invalid:6379/0")
    monkeypatch.setitem(sys.modules, "redis", None)

    assert extensions._limiter_storage_uri() == "memory://"


def test_csp_scripts_are_nonce_based_and_session_cookie_is_hardened(client):
    response = client.get("/health")

    csp = response.headers["Content-Security-Policy"]
    script_src = [part for part in csp.split(";") if "script-src" in part][0]
    assert "'self'" in script_src
    assert "nonce-" in script_src
    assert "'unsafe-inline'" not in script_src

    assert extensions.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert extensions.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
