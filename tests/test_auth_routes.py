def test_chat_sessions_requires_authentication(client):
    response = client.get("/api/chat/sessions")

    assert response.status_code == 401
    assert response.get_json()["auth_required"] is True


def test_triage_analyze_requires_csrf_before_auth(client):
    response = client.post("/api/triage/analyze", json={"artifact": "test"})

    assert response.status_code == 403
    assert response.get_json()["csrf_error"] is True

