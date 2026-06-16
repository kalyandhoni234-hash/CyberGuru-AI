from services.triage_service import _extract_structured


def test_extract_structured_prefers_json_block():
    text = """
1. Verdict: probably scary words in prose

```json
{"verdict": "likely_malicious", "severity": "critical"}
```
"""

    assert _extract_structured(text) == ("likely_malicious", "critical")


def test_extract_structured_falls_back_to_regex():
    text = "Verdict: suspicious\nSeverity: high\nReason: repeated failed logins"

    assert _extract_structured(text) == ("suspicious", "high")
