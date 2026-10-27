from services.triage_service import (
    _extract_structured,
    _extract_verdict_severity,
)


def test_extract_structured_prefers_json_block():
    text = """
1. Verdict: probably scary words in prose

```json
{"verdict": "likely_malicious", "severity": "critical"}
```
"""

    structured = _extract_structured(text)
    assert structured["verdict"] == "likely_malicious"
    assert structured["severity"] == "critical"
    assert structured["valid"] is True
    assert structured["iocs"] == []


def test_narrative_only_output_is_not_an_assessment():
    """The old regex fallback guessed a verdict from prose. It is gone:
    a free-form sentence must never be promoted to a valid assessment."""
    text = "Verdict: suspicious\nSeverity: high\nReason: repeated failed logins"

    structured = _extract_structured(text)
    assert structured["verdict"] is None
    assert structured["severity"] is None
    assert structured["valid"] is False
    assert structured["parse_error"] == "missing_assessment_block"


def test_word_benign_in_narrative_cannot_create_a_benign_verdict():
    text = "This is definitely not benign. Severity: low."
    assert _extract_verdict_severity(text) == (
        None,
        None,
        False,
        "missing_assessment_block",
    )


def test_malformed_json_is_invalid_not_coerced():
    text = '```json\n{"verdict": "benign", "severity": }\n```'
    verdict, severity, valid, error = _extract_verdict_severity(text)
    assert (verdict, severity, valid) == (None, None, False)
    assert error == "malformed_assessment_json"


def test_unsupported_values_are_invalid():
    text = '```json\n{"verdict": "totally_malicious", "severity": "catastrophic"}\n```'
    verdict, severity, valid, error = _extract_verdict_severity(text)
    assert (verdict, severity, valid) == (None, None, False)
    assert error == "unsupported_assessment_value"


def test_missing_severity_is_invalid():
    text = '```json\n{"verdict": "benign"}\n```'
    verdict, severity, valid, error = _extract_verdict_severity(text)
    assert (verdict, severity, valid) == (None, None, False)
    assert error == "unsupported_assessment_value"


def test_contradictory_blocks_are_invalid():
    text = (
        '```json\n{"verdict": "benign", "severity": "low"}\n```\n'
        '```json\n{"verdict": "likely_malicious", "severity": "critical"}\n```'
    )
    verdict, severity, valid, error = _extract_verdict_severity(text)
    assert (verdict, severity, valid) == (None, None, False)
    assert error == "contradictory_assessment_blocks"


def test_duplicate_identical_blocks_stay_valid():
    text = (
        '```json\n{"verdict": "suspicious", "severity": "medium"}\n```\n'
        '```json\n{"verdict": "suspicious", "severity": "medium"}\n```'
    )
    assert _extract_verdict_severity(text)[:3] == ("suspicious", "medium", True)


def test_json_block_contradicting_labelled_narrative_is_invalid():
    text = (
        "Verdict: benign\nSeverity: low\n\n"
        '```json\n{"verdict": "likely_malicious", "severity": "critical"}\n```'
    )
    verdict, severity, valid, error = _extract_verdict_severity(text)
    assert (verdict, severity, valid) == (None, None, False)
    assert error == "verdict_conflicts_with_narrative"


def test_severity_label_contradiction_is_invalid():
    text = (
        "Verdict: suspicious\nSeverity: critical\n\n"
        '```json\n{"verdict": "suspicious", "severity": "low"}\n```'
    )
    assert _extract_verdict_severity(text)[3] == "severity_conflicts_with_narrative"


def test_too_many_candidate_blocks_are_invalid():
    blocks = "\n".join(
        '```json\n{"verdict": "benign", "severity": "low"}\n```' for _ in range(6)
    )
    assert _extract_verdict_severity(blocks)[3] == "too_many_assessment_blocks"


def test_likely_malicious_alias_is_accepted():
    text = '```json\n{"verdict": "likely malicious", "severity": "high"}\n```'
    assert _extract_verdict_severity(text)[:3] == ("likely_malicious", "high", True)
