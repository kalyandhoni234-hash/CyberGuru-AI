"""
Deterministic, evidence-based confidence scoring (0-100).

Confidence reflects the STRENGTH and corroboration of the evidence behind
an assessment. It is deliberately kept independent of severity:

    severity   = how bad the finding is if it is real
    confidence = how sure we are that the assessment is correct

The score is derived entirely from structured pipeline data (threat-intel
results, MITRE ATT&CK mappings, extracted IOCs) so it is explainable,
consistent across runs, and unit-testable. The AI never asserts a
confidence number in prose.

Scoring model (documented thresholds)
-------------------------------------
External, independently verifiable signals:
  * AbuseIPDB confidence score >= 75  -> +45 (strong single source)
  * AbuseIPDB confidence score >= 40  -> +30 (moderate)
  * AbuseIPDB confidence score  >  0  -> +12 (weak signal)
  * VirusTotal malicious flags >= 10  -> +45 (strong)
  * VirusTotal malicious flags >=  3  -> +35 (moderate)
  * VirusTotal malicious flags  >  0  -> +25 (weak)
  * VirusTotal suspicious flags only  -> +10
  * More than one distinct VirusTotal IP with usable data -> +5
  * Two external providers with a malicious signal -> +5
  * Three or more external providers (future-proof) -> +10

Heuristic corroboration:
  * A MITRE ATT&CK mapping extracted from the model narrative -> +15.
    This is behavioural inference, NOT an externally verified source, so it
    never counts toward the multi-source bonus.

Deliberately NOT scored:
  * The mere existence of an extracted IOC. An indicator being present says
    nothing about whether it is malicious; the old +5 rule was removed.
  * Duplicate lookups of the same IP. Each provider is counted once per
    distinct indicator, no matter how many times the model called the tool.
  * Errors, timeouts, missing credentials, not_found responses, or
    not_applicable (private/documentation) addresses. None of these are
    treated as a clean result.
  * Malformed provider payloads (missing/NaN/non-numeric fields).

For clean (benign) assessments, a provider only corroborates the clean
verdict when it returned usable data and reported zero malicious (and, for
VirusTotal, zero suspicious) flags. Two clean providers cap at 60; with no
usable lookups the score stays honestly low (floor 5).

An ``inconclusive`` verdict is capped at 40: clean external lookups can show
that the checked indicators are not flagged, but they cannot make an
inconclusive assessment strong. If any external provider reports malice while
the model's verdict is benign or inconclusive, the conflicting evidence caps
the score at 25 and is named as a factor — the model's verdict never erases
the provider signal.

Limitations
-----------
This is a transparent heuristic, not a statistically calibrated probability.
The thresholds are policy choices, not learned weights. A score of 80 means
"multiple documented signals agree", not "80% chance of compromise".
Provider reputation is also incomplete: a clean result for an IP says
nothing about the rest of the artifact.

Everything is clamped to 0-100. A result with no corroborating evidence at
all floors at 5 rather than 0.
"""

IOC_KEYS = ("ips", "domains", "urls", "hashes", "emails")

_SUPPORTED_VERDICTS = {"benign", "suspicious", "likely_malicious", "inconclusive"}
_MALICIOUS_VERDICTS = {"likely_malicious", "suspicious"}


def _ioc_count(iocs) -> int:
    if not isinstance(iocs, dict):
        return 0
    total = 0
    for key in IOC_KEYS:
        values = iocs.get(key)
        if isinstance(values, list):
            total += len(values)
    return total


def _as_int(value):
    """Return a non-negative int, or None for missing/malformed values."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return number if number >= 0 else None


def _usable_provider_data(entries):
    """Yield usable provider payloads, one per distinct indicator.

    ``entries`` is a list of threat-intel entries shaped like
    ``{"ip": ..., "status": "ok", "result": {"data": {...}}}``. Entries that
    failed, were skipped, or carry malformed payloads are ignored. Repeated
    lookups of the same IP are deduplicated so they cannot inflate the score.
    """
    if not isinstance(entries, list):
        return
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip")
        key = str(ip) if ip else None
        if key and key in seen:
            continue
        status = entry.get("status")
        if status in ("error", "not_found", "not_applicable"):
            continue
        if "error" in entry and status != "ok":
            continue
        result = entry.get("result")
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            continue
        if key:
            seen.add(key)
        yield data


def compute_confidence_detail(
    verdict,
    severity=None,
    threat_intel=None,
    mitre_techniques=None,
    iocs=None,
) -> dict:
    """Return the score plus the deterministic factors that produced it.

    ``severity`` is accepted for signature clarity and intentionally unused:
    confidence must not change just because the incident is more severe.
    """
    threat_intel = threat_intel if isinstance(threat_intel, dict) else {}
    mitre_techniques = mitre_techniques if isinstance(mitre_techniques, list) else []
    iocs = iocs if isinstance(iocs, dict) else {}

    verdict = (verdict or "inconclusive").lower()
    if verdict not in _SUPPORTED_VERDICTS:
        verdict = "inconclusive"

    factors = []
    malicious_signals = 0
    clean_sources = 0
    external_sources_with_malice = 0

    # ── AbuseIPDB (distinct IPs only) ──
    max_abuse = 0
    abuse_usable = 0
    for data in _usable_provider_data(threat_intel.get("abuseipdb")):
        score = _as_int(data.get("abuseConfidenceScore"))
        if score is None or score > 100:
            continue
        abuse_usable += 1
        max_abuse = max(max_abuse, score)

    if max_abuse >= 75:
        malicious_signals += 45
        external_sources_with_malice += 1
        factors.append("AbuseIPDB confidence >= 75 (+45)")
    elif max_abuse >= 40:
        malicious_signals += 30
        external_sources_with_malice += 1
        factors.append("AbuseIPDB confidence >= 40 (+30)")
    elif max_abuse > 0:
        malicious_signals += 12
        external_sources_with_malice += 1
        factors.append("AbuseIPDB weak signal (+12)")
    elif abuse_usable:
        clean_sources += 1
        factors.append("AbuseIPDB usable and clean (+1 clean source)")

    # ── VirusTotal (distinct IPs only) ──
    vt_total_malicious = 0
    vt_total_suspicious = 0
    vt_usable = 0
    for data in _usable_provider_data(threat_intel.get("virustotal")):
        attributes = data.get("attributes")
        stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
        if not isinstance(stats, dict):
            continue
        malicious = _as_int(stats.get("malicious"))
        suspicious = _as_int(stats.get("suspicious"))
        if malicious is None:
            continue
        vt_usable += 1
        vt_total_malicious += malicious
        vt_total_suspicious += suspicious or 0

    if vt_total_malicious >= 10:
        malicious_signals += 45
        external_sources_with_malice += 1
        factors.append("VirusTotal malicious >= 10 (+45)")
    elif vt_total_malicious >= 3:
        malicious_signals += 35
        external_sources_with_malice += 1
        factors.append("VirusTotal malicious >= 3 (+35)")
    elif vt_total_malicious > 0:
        malicious_signals += 25
        external_sources_with_malice += 1
        factors.append("VirusTotal malicious > 0 (+25)")
    elif vt_usable and vt_total_suspicious > 0:
        malicious_signals += 10
        external_sources_with_malice += 1
        factors.append("VirusTotal suspicious flags only (+10)")
    elif vt_usable:
        clean_sources += 1
        factors.append("VirusTotal usable and clean (+1 clean source)")

    if vt_usable > 1:
        malicious_signals += 5
        factors.append("Multiple distinct VirusTotal IPs (+5)")

    # ── MITRE (heuristic, not an external source) ──
    if mitre_techniques:
        malicious_signals += 15
        factors.append("MITRE technique mapped (heuristic, +15)")

    # ── Multi-source agreement ──
    if external_sources_with_malice >= 3:
        malicious_signals += 10
        factors.append("3+ external sources agree (+10)")
    elif external_sources_with_malice >= 2:
        malicious_signals += 5
        factors.append("2 external sources agree (+5)")

    if verdict in _MALICIOUS_VERDICTS:
        base = malicious_signals
    elif external_sources_with_malice:
        # A non-malicious verdict contradicted by external provider evidence
        # must not gain confidence from an unrelated clean lookup.
        base = min(25, clean_sources * 10)
        factors.append(
            "External provider evidence conflicts with the "
            f"{verdict} verdict — score capped (+{base})"
        )
    elif verdict == "inconclusive":
        # Clean lookups say the checked IPs were not flagged; they do not make
        # an inconclusive assessment strong.
        base = min(40, clean_sources * 15)
    else:  # benign
        base = min(60, clean_sources * 30)

    score = max(5, min(100, base))
    if not factors:
        factors.append("No corroborating evidence (floor 5)")

    return {
        "score": score,
        "factors": factors,
        "malicious_signals": malicious_signals,
        "clean_sources": clean_sources,
        "external_sources_with_malice": external_sources_with_malice,
        "usable_abuse_lookups": abuse_usable,
        "usable_vt_lookups": vt_usable,
        "ioc_count": _ioc_count(iocs),
    }


def compute_confidence(
    verdict,
    severity=None,
    threat_intel=None,
    mitre_techniques=None,
    iocs=None,
) -> int:
    """Return a deterministic 0-100 confidence score for an assessment."""
    return compute_confidence_detail(
        verdict=verdict,
        severity=severity,
        threat_intel=threat_intel,
        mitre_techniques=mitre_techniques,
        iocs=iocs,
    )["score"]
