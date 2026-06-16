from routes import chat as chat_routes


def test_persist_turn_saves_messages_with_authenticated_user(monkeypatch):
    calls = []

    def fake_save_message(session_id, user_id, role, content):
        calls.append((session_id, user_id, role, content))
        return {"id": len(calls)}

    monkeypatch.setattr(chat_routes, "get_user_id_int", lambda: 42)
    monkeypatch.setattr(chat_routes, "save_message", fake_save_message)

    chat_routes._persist_turn(7, "hello", "hi there")

    assert calls == [
        (7, 42, "user", "hello"),
        (7, 42, "bot", "hi there"),
    ]


def test_persist_turn_skips_when_user_is_missing(monkeypatch):
    calls = []

    monkeypatch.setattr(chat_routes, "get_user_id_int", lambda: None)
    monkeypatch.setattr(chat_routes, "save_message", lambda *args: calls.append(args))

    chat_routes._persist_turn(7, "hello", "hi there")

    assert calls == []


def test_persist_turn_tolerates_unowned_session(monkeypatch):
    monkeypatch.setattr(chat_routes, "get_user_id_int", lambda: 42)
    monkeypatch.setattr(chat_routes, "save_message", lambda *args: None)

    chat_routes._persist_turn(999, "hello", "hi there")

