def test_investigate_history_requires_authentication(client):
    response = client.get("/api/investigate/history")

    assert response.status_code == 401
    assert response.get_json()["auth_required"] is True


def test_investigate_page_redirects_anonymous_users_to_landing(client):
    response = client.get("/investigate")

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_root_renders_landing_for_anonymous_users(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"SOC Investigation Center" in response.data


def test_root_renders_investigation_center_for_authenticated_users(authenticated_client):
    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert b"Evidence Workspace" in response.data


def test_triage_analyze_requires_csrf_before_business_logic(authenticated_client):
    response = authenticated_client.post("/api/triage/analyze", json={"artifact": "test"})

    assert response.status_code == 403
    assert response.get_json()["csrf_error"] is True
