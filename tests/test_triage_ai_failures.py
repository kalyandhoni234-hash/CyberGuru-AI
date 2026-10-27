"""AI-provider failure semantics for ``analyze_artifact``.

An execution error, safety block, or invalid output must never become a
benign/low-risk assessment. A genuine model-produced ``inconclusive`` verdict
is different: it is a valid assessment and must survive validation.
"""

from types import SimpleNamespace

import services.triage_service as triage


class FakeResponse:
    def __init__(self, text=None, candidates=None, raise_on_text=False):
        self._text = text
        self.candidates = candidates if candidates is not None else []
        self.prompt_feedback = None
        self._raise_on_text = raise_on_text

    @property
    def text(self):
        if self._raise_on_text:
            raise ValueError("safety blocked")
        return self._text


def _candidate(finish_reason=None):
    return SimpleNamespace(
        finish_reason=finish_reason,
        content=SimpleNamespace(parts=[]),
        safety_ratings=[],
    )


def _fake_call(monkeypatch, response=None, error_code=None):
    monkeypatch.setattr(
        triage,
        "_model_call",
        lambda contents, config: (response, error_code),
    )


def test_provider_timeout_returns_error_and_no_verdict(monkeypatch):
    _fake_call(monkeypatch, response=None, error_code="timeout")

    result = triage.analyze_artifact("some evidence")

    assert result["status"] == "error"
    assert result["assessment_valid"] is False
    assert result["error_code"] == "timeout"
    assert result["verdict"] is None
    assert result["severity"] is None


def test_rate_limit_returns_error_code(monkeypatch):
    _fake_call(monkeypatch, response=None, error_code="rate_limited")

    result = triage.analyze_artifact("some evidence")
    assert result["status"] == "error"
    assert result["error_code"] == "rate_limited"
    assert result["verdict"] is None


def test_safety_block_is_not_an_inconclusive_assessment(monkeypatch):
    _fake_call(
        monkeypatch,
        response=FakeResponse(
            candidates=[_candidate(finish_reason="SAFETY")],
            raise_on_text=True,
        ),
    )

    result = triage.analyze_artifact("blocked content")
    assert result["status"] == "error"
    assert result["error_code"] == "blocked"
    assert result["verdict"] is None


def test_invalid_output_is_not_a_valid_assessment(monkeypatch):
    response = FakeResponse(
        text="The artifact looks fine, nothing to worry about.",
        candidates=[_candidate()],
    )
    _fake_call(monkeypatch, response=response)

    result = triage.analyze_artifact("evidence")
    assert result["status"] == "invalid_output"
    assert result["assessment_valid"] is False
    assert result["error_code"] == "missing_assessment_block"
    assert result["verdict"] is None
    assert result["analysis"]  # narrative retained for diagnostics


def test_valid_inconclusive_assessment_is_preserved(monkeypatch):
    response = FakeResponse(
        text=(
            "Verdict: inconclusive\nSeverity: low\n\n"
            '```json\n{"verdict": "inconclusive", "severity": "low"}\n```'
        ),
        candidates=[_candidate()],
    )
    _fake_call(monkeypatch, response=response)

    result = triage.analyze_artifact("ambiguous evidence")
    assert result["status"] == "completed"
    assert result["assessment_valid"] is True
    assert result["verdict"] == "inconclusive"
    assert result["severity"] == "low"


def test_unsupported_artifact_type_fails_before_provider_call(monkeypatch):
    monkeypatch.setattr(
        triage,
        "_model_call",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call AI")),
    )

    result = triage.analyze_artifact("evidence", "not-a-type")
    assert result["status"] == "error"
    assert result["error_code"] == "invalid_type"
    assert result["verdict"] is None
