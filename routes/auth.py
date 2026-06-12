from flask import jsonify, redirect, url_for, session

from extensions import app, google, csrf_protect, _get_csrf_token
from services.db_service import upsert_user


@app.route("/auth/csrf-token", methods=["GET"])
def get_csrf_token():
    """Frontend calls this once on load to obtain a CSRF token."""
    return jsonify({"csrf_token": _get_csrf_token()})


@app.route("/auth/login")
def auth_login():
    """Redirect the browser to Google's OAuth consent screen."""
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    """Google redirects here after user approves. Exchange code → tokens → user info."""
    token = google.authorize_access_token()
    userinfo = token.get("userinfo") or google.userinfo()
    google_id = userinfo["sub"]
    email     = userinfo.get("email", "")
    name      = userinfo.get("name", email)
    avatar    = userinfo.get("picture", "")

    user = upsert_user(google_id, email, name, avatar)

    session.permanent = True
    session["user"] = {
        "id":     user["id"],
        "google_id": google_id,
        "email":  email,
        "name":   name,
        "avatar": avatar,
    }
    return redirect("/")


@app.route("/auth/logout", methods=["POST"])
@csrf_protect
def auth_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/auth/me")
def auth_me():
    """Returns current session user, or 401 if not logged in."""
    user = session.get("user")
    if not user:
        return jsonify({"user": None}), 401
    return jsonify({"user": user})
