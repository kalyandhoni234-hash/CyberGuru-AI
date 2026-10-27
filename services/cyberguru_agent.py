"""Investigation orchestration.

The orchestrator is the single source of truth for what actually happened in
an investigation.  It never marks a stage as completed on the strength of the
HTTP request succeeding: each stage carries the outcome of the work it
represents, and the overall status distinguishes a valid assessment from a
failed or unvalidated AI run.

Contract
--------
``investigate()`` returns a dict with (at minimum):

    status              completed | partial | failed
    analysis_valid      bool — True only for a strictly validated assessment
    analysis            the triage result (narrative, verdict, severity, ...)
    analysis_error      sanitized error message when analysis_valid is False
    iocs, threat_intel, mitre, mitre_techniques
    confidence          int (0 when there is no valid assessment)
    confidence_factors  human-readable explanation of the score
    evidence            deterministic E-ID registry
    recommendations     evidence-specific next steps
    report              deterministic incident report
    pipeline            per-stage {step, name, label, status, detail}
    analyst_status/notes
    investigation_id
    artifact_type
"""

import hashlib
import logging

from utils.ioc_extractor import extract_iocs
from utils.report_generator import generate_incident_report
from utils.confidence import compute_confidence_detail
from utils.evidence import build_evidence
from utils.recommendations import build_specific_recommendations
from utils.db_service import save_investigation, find_recent_investigation

from services.triage_service import (
    SUPPORTED_ARTIFACT_TYPES,
    SUPPORTED_SEVERITIES,
    SUPPORTED_VERDICTS,
    analyze_artifact,
)


# How long a cached investigation result is considered "fresh" enough
# to skip re-running the full pipeline for an identical artifact.
logger = logging.getLogger(__name__)

DEDUPE_WINDOW_HOURS = 24

# Stage states.  `partial` is used when an optional provider returned some
# usable data and some failures; it is never a synonym for success.
STAGE_COMPLETED = "completed"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"
STAGE_PARTIAL = "partial"


def _threat_entry(ip, result):
    """Normalise a threat-intel tool-call result into a threat-intel entry.

    The ok/error/not_applicable/not_found status is preserved so downstream
    consumers can render each state distinctly instead of pretending a
    skipped lookup was a clean one.
    """
    entry = {"ip": ip}
    status = result.get("status")
    if status == "not_applicable":
        entry["status"] = "not_applicable"
        entry["reason"] = result.get("reason") or "Not Applicable"
    elif status == "not_found":
        entry["status"] = "not_found"
        entry["message"] = result.get("message") or "No results found"
    elif status == "error" or "error" in result:
        entry["status"] = "error"
        entry["error_code"] = result.get("error_code") or "provider_error"
        entry["error"] = result.get("error") or "Lookup failed"
    else:
        entry["status"] = "ok"
        entry["result"] = result
    return entry


def _hash_artifact(artifact_text, artifact_type="auto"):
    """Hash the artifact together with its analysis type.

    Including the type prevents a cached "auto" result from being served for
    an explicit log/email/URL analysis of the same bytes.  Rows written before
    Phase 0 used the text alone; they simply stop matching, which is safer
    than returning a result produced under different instructions.
    """
    normalized_type = (artifact_type or "auto").strip().lower()
    seed = f"{normalized_type}\n{artifact_text.strip()}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _is_valid_analysis(analysis):
    """Return True only for a completed, strictly validated assessment."""
    if not isinstance(analysis, dict):
        return False
    if analysis.get("status") != "completed":
        return False
    if analysis.get("assessment_valid") is not True:
        return False
    return (
        analysis.get("verdict") in SUPPORTED_VERDICTS
        and analysis.get("severity") in SUPPORTED_SEVERITIES
    )


def _stage(step, name, label, status, detail=""):
    return {
        "step": step,
        "name": name,
        "label": label,
        "status": status,
        "detail": detail,
    }


def _threat_intel_stage_state(threat_intel):
    """Describe the threat-intel stage truthfully.

    - no entries at all            -> skipped (nothing was queried)
    - only non-routable addresses  -> skipped (provider intentionally not called)
    - every provider call failed   -> failed
    - mix of success and failure   -> partial
    - otherwise                    -> completed
    """
    entries = list(threat_intel.get("abuseipdb") or []) + list(threat_intel.get("virustotal") or [])
    if not entries:
        return STAGE_SKIPPED, "No public IP indicators were looked up."
    if all(entry.get("status") == "not_applicable" for entry in entries):
        return STAGE_SKIPPED, "No routable IPs required a threat-intel lookup."
    errors = [entry for entry in entries if entry.get("status") == "error"]
    if len(errors) == len(entries):
        return STAGE_FAILED, "All threat-intelligence lookups failed."
    if errors:
        return STAGE_PARTIAL, f"{len(errors)} of {len(entries)} threat-intel lookups failed."
    return STAGE_COMPLETED, f"{len(entries)} threat-intel lookup(s) completed."


def _build_pipeline(
    iocs_stage,
    artifact_type,
    threat_intel,
    mitre_techniques,
    analysis_valid,
    report_status=STAGE_COMPLETED,
    report_detail="Deterministic report generated.",
):
    """Build the seven-stage pipeline with real outcomes."""
    threat_status, threat_detail = _threat_intel_stage_state(threat_intel)

    if mitre_techniques:
        mitre_status = STAGE_COMPLETED
        mitre_detail = f"{len(mitre_techniques)} technique(s) mapped."
    else:
        mitre_status = STAGE_SKIPPED
        mitre_detail = "No MITRE technique was mapped."

    ai_status = STAGE_COMPLETED if analysis_valid else STAGE_FAILED
    ai_detail = (
        "Assessment validated."
        if analysis_valid
        else "No valid assessment was produced."
    )

    return [
        iocs_stage,
        _stage(2, "parse", "Parsing Evidence", iocs_stage["status"], iocs_stage["detail"]),
        _stage(3, "threat_intel", "Threat Intelligence Lookup", threat_status, threat_detail),
        _stage(4, "mitre", "MITRE ATT&CK Mapping", mitre_status, mitre_detail),
        _stage(5, "risk", "Risk Assessment",
               STAGE_COMPLETED if analysis_valid else STAGE_FAILED,
               "Risk derived from a validated severity."
               if analysis_valid else "No validated severity to score."),
        _stage(6, "ai_analysis", "AI Analysis", ai_status, ai_detail),
        _stage(7, "report", "Report Generation", report_status, report_detail),
    ]


def _overall_status(analysis_valid, pipeline):
    if not analysis_valid:
        return STAGE_FAILED
    if any(stage["status"] in (STAGE_FAILED, STAGE_PARTIAL) for stage in pipeline):
        return STAGE_PARTIAL
    return STAGE_COMPLETED


def _collect_threat_intel(tool_calls):
    """Collect deduplicated threat-intel entries from the model's tool calls."""
    threat_intel = {"abuseipdb": [], "virustotal": []}
    seen = set()

    for call in tool_calls or []:
        if not isinstance(call, dict):
            continue
        name = call.get("name")
        args = call.get("args") or {}
        ip = args.get("ip")
        key = (name, str(ip))
        if key in seen:
            continue
        seen.add(key)

        result = call.get("result")
        if not isinstance(result, dict):
            continue

        if name == "check_abuseipdb":
            threat_intel["abuseipdb"].append(_threat_entry(ip, result))
        elif name == "check_virustotal_ip":
            threat_intel["virustotal"].append(_threat_entry(ip, result))

    return threat_intel


def investigate(artifact_text, user_id=None, allow_cached=True, artifact_type="auto"):
    """Run the investigation pipeline.

    ``artifact_type`` must be one of ``SUPPORTED_ARTIFACT_TYPES``.  The route
    validates it for HTTP callers; this function validates again so internal
    callers cannot bypass the contract.
    """
    if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
        raise ValueError("Unsupported artifact type")

    artifact_type = (artifact_type or "auto").strip().lower()
    artifact_hash = _hash_artifact(artifact_text, artifact_type)

    # Cache is only ever consulted for an authenticated, user-scoped request.
    if allow_cached and user_id is not None:
        cached = find_recent_investigation(
            artifact_hash, user_id, max_age_hours=DEDUPE_WINDOW_HOURS
        )
        if cached:
            return result_from_db_row(cached, from_cache=True)

    # Stage 1: IOC extraction (deterministic, independent of the model).
    extraction_error = None
    try:
        iocs = extract_iocs(artifact_text)
        iocs_stage = _stage(
            1, "extract_iocs", "Extracting Indicators", STAGE_COMPLETED,
            f"{sum(len(v) for v in iocs.values())} indicator(s) extracted.",
        )
    except Exception:
        iocs = {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
        extraction_error = "Indicator extraction failed."
        iocs_stage = _stage(
            1, "extract_iocs", "Extracting Indicators", STAGE_FAILED,
            extraction_error,
        )

    # Stage 2: AI triage (the model decides its own tool calls).
    analysis = analyze_artifact(artifact_text, artifact_type)
    analysis_valid = _is_valid_analysis(analysis)
    if analysis_valid:
        analysis_error = None
    else:
        analysis_error = analysis.get("error") or "AI assessment was not valid."

    threat_intel = _collect_threat_intel(analysis.get("tool_calls"))
    mitre_techniques = analysis.get("mitre_techniques") or [] if analysis_valid else []
    mitre = mitre_techniques[0] if mitre_techniques else None
    verdict = analysis.get("verdict") if analysis_valid else None
    severity = analysis.get("severity") if analysis_valid else None

    # Stage 6: confidence.  An invalid assessment has no confidence, not a
    # low confidence: 0 makes the missing assessment explicit.  Computed
    # before recommendations so fresh runs and stored reloads see the same
    # confidence (result_from_db_row passes the stored score).
    if analysis_valid:
        confidence_detail = compute_confidence_detail(
            verdict=verdict,
            severity=severity,
            threat_intel=threat_intel,
            mitre_techniques=mitre_techniques,
            iocs=iocs,
        )
    else:
        confidence_detail = {
            "score": 0,
            "factors": ["Assessment invalid — confidence not computed."],
        }
    confidence = confidence_detail["score"]

    # Stage 7: deterministic report and recommendations.  These should not
    # fail, but if they do the stage is reported as failed rather than
    # pretending a complete report exists.
    report_status = STAGE_COMPLETED
    report_detail = "Deterministic report generated."
    try:
        recommendations = build_specific_recommendations(
            iocs=iocs,
            threat_intel=threat_intel,
            mitre_techniques=mitre_techniques,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            analysis_valid=analysis_valid,
        )
        report = generate_incident_report(
            verdict=verdict,
            severity=severity,
            iocs=iocs,
            mitre=mitre,
            threat_intel=threat_intel,
            analysis_error=analysis_error,
            recommendations=recommendations,
            summary=analysis.get("analysis") or analysis.get("summary") or "",
            artifact_type=artifact_type,
        )
    except Exception:
        logger.exception("Investigation report generation failed")
        recommendations = [
            "Report generation failed — review the raw indicators manually."
        ]
        report = "Incident Report\n\nReport generation failed; see raw indicators."
        report_status = STAGE_FAILED
        report_detail = "Deterministic report generation failed."

    evidence = build_evidence(
        iocs=iocs,
        threat_intel=threat_intel,
        mitre_techniques=mitre_techniques,
    )

    pipeline = _build_pipeline(
        iocs_stage,
        artifact_type,
        threat_intel,
        mitre_techniques,
        analysis_valid,
        report_status=report_status,
        report_detail=report_detail,
    )
    status = _overall_status(analysis_valid, pipeline)

    # Persist only when we have an authenticated owner.  Failed analyses are
    # stored for history/diagnostics but are excluded from the cache query.
    investigation_id = None
    if user_id is not None:
        row = save_investigation(
            user_id=user_id,
            artifact_hash=artifact_hash,
            artifact_text=artifact_text,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            mitre=mitre,
            iocs=iocs,
            threat_intel=threat_intel,
            report=report,
            analysis_error=analysis_error,
            analysis_text=analysis.get("analysis"),
            analysis_valid=analysis_valid,
            artifact_type=artifact_type,
        )
        investigation_id = row.get("id") if row else None

    return {
        "status": status,
        "analysis_valid": analysis_valid,
        "analysis": analysis,
        "analysis_error": analysis_error,
        "iocs": iocs,
        "threat_intel": threat_intel,
        "mitre": mitre,
        "mitre_techniques": mitre_techniques,
        "confidence": confidence,
        "confidence_factors": confidence_detail["factors"],
        "evidence": evidence,
        "recommendations": recommendations,
        "report": report,
        "pipeline": pipeline,
        "from_cache": False,
        "investigation_id": investigation_id,
        "analyst_status": "New",
        "analyst_notes": "",
        "artifact_type": artifact_type,
    }


def result_from_db_row(row, from_cache=False):
    """Reconstruct the full investigation contract from a saved DB row.

    Public because the history/detail endpoints need exactly the same
    contract as a cache hit: an investigation read back from storage must not
    lose its verdict, narrative, evidence, or stage outcomes.
    """
    def get(key, default=None):
        return row.get(key, default) if row is not None else default

    iocs = get("iocs") if isinstance(get("iocs"), dict) else {}
    threat_intel = get("threat_intel") if isinstance(get("threat_intel"), dict) else {}

    mitre = None
    if get("mitre_id"):
        mitre = {"id": get("mitre_id"), "name": get("mitre_name")}
    mitre_techniques = [mitre] if mitre else []

    # Legacy rows predate analysis_valid.  Treat them as valid only when they
    # have no recorded error and carry a supported verdict/severity.
    stored_valid = get("analysis_valid")
    if stored_valid is None:
        analysis_valid = (
            not get("analysis_error")
            and get("verdict") in SUPPORTED_VERDICTS
            and get("severity") in SUPPORTED_SEVERITIES
        )
    else:
        analysis_valid = bool(stored_valid)

    analysis_text = get("analysis_text")
    if analysis_valid:
        analysis_status = "completed"
    elif analysis_text:
        analysis_status = "invalid_output"
    else:
        analysis_status = "error"

    verdict = get("verdict") if analysis_valid else None
    severity = get("severity") if analysis_valid else None
    confidence = get("confidence") if analysis_valid else 0
    try:
        confidence = int(confidence or 0)
    except (TypeError, ValueError):
        confidence = 0
    confidence = max(0, min(100, confidence))

    recommendations = build_specific_recommendations(
        iocs=iocs,
        threat_intel=threat_intel,
        mitre_techniques=mitre_techniques,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        analysis_valid=analysis_valid,
    )
    evidence = build_evidence(
        iocs=iocs,
        threat_intel=threat_intel,
        mitre_techniques=mitre_techniques,
    )

    analysis = {
        "verdict": verdict,
        "severity": severity,
        "summary": analysis_text or "",
        "status": analysis_status,
        "assessment_valid": analysis_valid,
        "valid": analysis_valid,
        "error": get("analysis_error"),
        "analysis": analysis_text or "",
    }

    stored_report = get("report") or ""
    pipeline = _build_pipeline(
        _stage(1, "extract_iocs", "Extracting Indicators", STAGE_COMPLETED,
               "Indicators were extracted when the investigation ran."),
        get("artifact_type") or "auto",
        threat_intel,
        mitre_techniques,
        analysis_valid,
        report_status=STAGE_COMPLETED if stored_report else STAGE_FAILED,
        report_detail=(
            "Stored report loaded."
            if stored_report else "No report was stored for this investigation."
        ),
    )
    status = _overall_status(analysis_valid, pipeline)
    for stage in pipeline:
        stage["detail"] = f"{stage['detail']} (reconstructed from stored result)"

    return {
        "status": status,
        "analysis_valid": analysis_valid,
        "analysis": analysis,
        "analysis_error": get("analysis_error"),
        "iocs": iocs,
        "threat_intel": threat_intel,
        "mitre": mitre,
        "mitre_techniques": mitre_techniques,
        "confidence": confidence,
        "confidence_factors": ["Stored result — original scoring factors are not stored."],
        "evidence": evidence,
        "recommendations": recommendations,
        "report": get("report") or "",
        "pipeline": pipeline,
        "from_cache": from_cache,
        "investigation_id": get("id"),
        "analyst_status": get("analyst_status") or "New",
        "analyst_notes": get("analyst_notes") or "",
        "artifact_type": get("artifact_type") or "auto",
    }
