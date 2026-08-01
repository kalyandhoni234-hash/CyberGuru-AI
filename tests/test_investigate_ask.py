"""
tests/test_investigate_ask.py
=============================
Integration tests for the investigation-scoped AI copilot endpoint:

  POST /api/investigate/ask

Covers the streaming contract end-to-end:
  - A successful answer streams `data:` token events and ends with `{"done": true}`.
  - A mid-stream Gemini failure (rate limit / service error / timeout) emits a
    single SSE `data:` error event and does NOT emit a `done` event.
  - Request validation (missing question, bad id, unknown investigation).

Gemini is faked via monkeypatch of routes.analyze.gemini_post and
routes.analyze.get_investigation_by_id so no network or database is touched.
"""

import json

import pytest
import requests

from services.gemini_service import GeminiRateLimitError, GeminiServiceError

CSRF_HEADER = {"X-CSRF-Token": "csrf-test-token"}

# A saved investigation row in the same shape db_service returns.
FAKE_ROW = {
    "id": 1,
    "verdict": "suspicious",
    "severity": "high",
    "mitre_id": "T1059",
    "mitre_name": "Command and Scripting Interpreter",
    "iocs": {
        "ips": ["8.8.8.8"],
        "domains": ["evil.example.com"],
        "urls": ["https://evil.example.com/payload"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "emails": ["phisher@evil.example.com"],
    },
    "artifact_text": "suspicious log line from infected host",
    "report": "## Incident Report\nHost contacted evil.example.com.",
}

# Gemini SSE lines as produced by the API (text content only).
TOKEN_LINES = [
    b'data: {"candidates":[{"content":{"parts":[{"text":"The verdict is "}]}}]}',
    b'data: {"candidates":[{"content":{"parts":[{"text":"suspicious. "}]}}]}',
    b'data: {"candidates":[{"content":{"parts":[{"text":"Severity: high."}]}}]}',
]


class FakeGeminiResp:
    """Minimal stand-in for requests.Response with iter_lines()."""

    def __init__(self, lines=None, error=None):
        self._lines = list(lines or [])
        self._error = error

    def iter_lines(self):
        if self._error is not None:
            raise self._error
        for line in self._lines:
            yield line


def _parse_sse(body: str) -> list:
    """Split an SSE payload into its parsed `data:` events."""
    events = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        for line in block.splitlines():
            if line.startswith("data: "):
                events.append(json.loads(line[len("data: "):]))
    return events


def _patch_copilot(monkeypatch, resp):
    monkeypatch.setattr(
        "routes.analyze.get_investigation_by_id",
        lambda investigation_id, user_id: FAKE_ROW,
    )
    monkeypatch.setattr("routes.analyze.gemini_post", lambda *a, **k: resp)


# ══════════════════════════════════════════════════════════════════════
# Happy path — SSE token stream ending in a `done` event
# ══════════════════════════════════════════════════════════════════════

class TestCopilotStreaming:
    def test_ask_streams_tokens_and_ends_with_done(self, authenticated_client, monkeypatch):
        _patch_copilot(monkeypatch, FakeGeminiResp(lines=TOKEN_LINES))

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": 1, "question": "What is the verdict?"},
            headers=CSRF_HEADER,
        )

        assert resp.status_code == 200
        assert resp.content_type.startswith("text/event-stream")

        events = _parse_sse(resp.get_data(as_text=True))
        assert events, "Expected at least one SSE event"

        token_events = [e for e in events if "token" in e]
        assert token_events, "Expected at least one `token` event"
        joined = "".join(e["token"] for e in token_events)
        assert "suspicious" in joined, f"Tokens should carry the model text, got: {joined!r}"

        assert events[-1] == {"done": True}, (
            f"Stream must end with {{'done': True}}, got: {events[-1]!r}"
        )

    def test_ask_includes_grounding_context_in_payload(self, authenticated_client, monkeypatch):
        """The payload sent to Gemini must be grounded in the saved investigation
        (IOCs, verdict, MITRE, artifact, report) rather than a free-form prompt."""
        captured = {}

        def fake_post(url, payload, **kwargs):
            captured["payload"] = payload
            return FakeGeminiResp(lines=TOKEN_LINES)

        monkeypatch.setattr(
            "routes.analyze.get_investigation_by_id",
            lambda investigation_id, user_id: FAKE_ROW,
        )
        monkeypatch.setattr("routes.analyze.gemini_post", fake_post)

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": 1, "question": "How should I remediate this?"},
            headers=CSRF_HEADER,
        )
        assert resp.status_code == 200

        contents = captured["payload"]["contents"]
        user_part = contents[0]["parts"][0]["text"]
        assert "8.8.8.8" in user_part, "Context should include extracted IP IOCs"
        assert "evil.example.com" in user_part, "Context should include extracted domains"
        assert "T1059" in user_part, "Context should include the MITRE mapping"
        assert "suspicious log line" in user_part, "Context should include the artifact text"
        assert "Incident Report" in user_part, "Context should include the report"

        system = captured["payload"]["system_instruction"]["parts"][0]["text"]
        assert "investigation context" in system, (
            "Copilot system instruction should demand grounding in the investigation"
        )


# ══════════════════════════════════════════════════════════════════════
# Error paths — mid-stream Gemini failures emit a single SSE error event
# ══════════════════════════════════════════════════════════════════════

class TestCopilotErrorEvents:
    @pytest.mark.parametrize("error", [
        GeminiRateLimitError(),
        GeminiServiceError(status_code=503),
        requests.exceptions.Timeout(),
    ])
    def test_midstream_gemini_error_emits_sse_error_event(
        self, authenticated_client, monkeypatch, error
    ):
        _patch_copilot(monkeypatch, FakeGeminiResp(error=error))

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": 1, "question": "Explain this IOC."},
            headers=CSRF_HEADER,
        )

        assert resp.status_code == 200
        assert resp.content_type.startswith("text/event-stream")

        events = _parse_sse(resp.get_data(as_text=True))
        assert events, "Expected at least one SSE event"

        error_events = [e for e in events if "error" in e]
        assert error_events, f"Expected an SSE error event, got: {events!r}"

        done_events = [e for e in events if e.get("done") is True]
        assert not done_events, "Error streams must not emit a `done` event"


# ══════════════════════════════════════════════════════════════════════
# Validation — request-shape guards fire before any Gemini call
# ══════════════════════════════════════════════════════════════════════

class TestCopilotValidation:
    def test_missing_question_returns_400(self, authenticated_client, monkeypatch):
        called = []
        monkeypatch.setattr(
            "routes.analyze.gemini_post",
            lambda *a, **k: called.append(1) or FakeGeminiResp(lines=TOKEN_LINES),
        )

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": 1, "question": "   "},
            headers=CSRF_HEADER,
        )

        assert resp.status_code == 400
        assert not called, "Gemini must not be called for an empty question"

    def test_non_integer_investigation_id_returns_400(self, authenticated_client, monkeypatch):
        called = []
        monkeypatch.setattr(
            "routes.analyze.gemini_post",
            lambda *a, **k: called.append(1) or FakeGeminiResp(lines=TOKEN_LINES),
        )

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": "not-a-number", "question": "hi"},
            headers=CSRF_HEADER,
        )

        assert resp.status_code == 400
        assert not called

    def test_unknown_investigation_returns_404(self, authenticated_client, monkeypatch):
        """get_investigation_by_id returning None → 404 before any Gemini call."""
        called = []
        monkeypatch.setattr(
            "routes.analyze.get_investigation_by_id",
            lambda investigation_id, user_id: None,
        )
        monkeypatch.setattr(
            "routes.analyze.gemini_post",
            lambda *a, **k: called.append(1) or FakeGeminiResp(lines=TOKEN_LINES),
        )

        resp = authenticated_client.post(
            "/api/investigate/ask",
            json={"investigation_id": 999, "question": "hi"},
            headers=CSRF_HEADER,
        )

        assert resp.status_code == 404
        assert resp.get_json()["error"] == "Investigation not found."
        assert not called, "Gemini must not be called for an unknown investigation"
