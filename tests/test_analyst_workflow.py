"""Tests for the analyst workflow endpoints (status + notes updates)."""

import pytest

from routes import investigate_center

CSRF_HEADER = {"X-CSRF-Token": "csrf-test-token"}


@pytest.fixture
def authenticated_client(flask_app):
    client = flask_app.test_client()
    with client.session_transaction() as s:
        s["user"] = {"id": 42, "email": "tester@example.com"}
        s["csrf_token"] = "csrf-test-token"
    return client


class TestUpdateAnalystState:
    def test_updates_status_and_notes(self, authenticated_client, monkeypatch):
        captured = {}

        def fake_update(investigation_id, user_id, status, notes):
            captured.update(id=investigation_id, user_id=user_id, status=status, notes=notes)
            return {"id": 1, "analyst_status": status, "analyst_notes": notes}

        monkeypatch.setattr(investigate_center, "update_investigation_analyst", fake_update)

        resp = authenticated_client.patch(
            "/api/investigate/5",
            json={"status": "In Review", "notes": "Sent to IR team"},
            headers=CSRF_HEADER,
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["analyst_status"] == "In Review"
        assert captured["status"] == "In Review"
        assert captured["notes"] == "Sent to IR team"

    def test_rejects_unknown_status(self, authenticated_client, monkeypatch):
        monkeypatch.setattr(
            investigate_center,
            "update_investigation_analyst",
            lambda *a, **k: {"id": 1, "analyst_status": "Bogus"},
        )
        resp = authenticated_client.patch(
            "/api/investigate/5", json={"status": "Bogus"}, headers=CSRF_HEADER
        )
        assert resp.status_code == 400

    def test_status_is_required(self, authenticated_client, monkeypatch):
        monkeypatch.setattr(
            investigate_center,
            "update_investigation_analyst",
            lambda *a, **k: {"id": 1},
        )
        resp = authenticated_client.patch("/api/investigate/5", json={}, headers=CSRF_HEADER)
        assert resp.status_code == 400

    def test_missing_investigation_returns_404(self, authenticated_client, monkeypatch):
        monkeypatch.setattr(
            investigate_center, "update_investigation_analyst", lambda *a, **k: None
        )
        resp = authenticated_client.patch(
            "/api/investigate/999", json={"status": "Resolved"}, headers=CSRF_HEADER
        )
        assert resp.status_code == 404


class TestAnalystStateInResponses:
    def test_analyze_response_defaults_to_new(self, authenticated_client):
        """A fresh investigation starts in the New state."""
        resp = authenticated_client.post(
            "/api/investigate/analyze",
            json={"artifact": "failed login from 8.8.8.8"},
            headers=CSRF_HEADER,
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["analyst_status"] == "New"
        assert body["analyst_notes"] == ""
