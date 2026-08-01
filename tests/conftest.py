import os
import sys
import types

import pytest


os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
os.environ.setdefault("FLASK_SECRET_KEY", "test-flask-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://example.invalid/test")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-client-secret")
# Pin rate-limit storage to in-memory BEFORE any module calls load_dotenv()
# (services/triage_service.py does), otherwise the real .env REDIS_URL
# (Upstash) gets injected and Flask-Limiter tries to reach it during tests.
os.environ.setdefault("REDIS_URL", "memory://")


def _install_route_stubs():
    db_stub = types.ModuleType("services.db_service")
    db_stub.get_investigation_history = lambda user_id, limit=20: []
    db_stub.get_investigation_by_id = lambda investigation_id, user_id: None
    db_stub.delete_investigation = lambda investigation_id, user_id: False
    db_stub.find_recent_investigation = lambda artifact_hash, user_id, max_age_hours=24: None
    db_stub.save_investigation = lambda *args, **kwargs: {"id": 1}
    db_stub.upsert_user = lambda google_id, email, name, avatar: {"id": 1}
    db_stub.init_db = lambda: None
    sys.modules.setdefault("services.db_service", db_stub)

    agent_stub = types.ModuleType("services.cyberguru_agent")
    agent_stub.investigate = lambda artifact, user_id=None: {
        "report": "test report",
        "analysis": {"status": "completed", "verdict": "benign", "severity": "low"},
        "mitre": None,
        "from_cache": False,
    }
    sys.modules.setdefault("services.cyberguru_agent", agent_stub)


_install_route_stubs()


@pytest.fixture(scope="session")
def flask_app():
    from extensions import app
    from routes import analyze, triage, investigate_center, misc, auth, seo  # noqa: F401

    app.config.update(TESTING=True, RATELIMIT_ENABLED=False)
    return app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def authenticated_client(client):
    with client.session_transaction() as session:
        session["user"] = {"id": 42, "email": "tester@example.com"}
        session["csrf_token"] = "csrf-test-token"
    return client
