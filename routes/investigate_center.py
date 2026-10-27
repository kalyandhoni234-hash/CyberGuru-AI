"""
Investigation Center — Dedicated SOC workspace for artifact analysis.

Endpoints:
  GET  /                               — Smart root: landing page when logged out,
                                         Investigation Center when authenticated.
  GET  /investigate                    — Serve the Investigation Center page (gated).
  POST /api/investigate/analyze        — Run full investigation pipeline.
  GET  /api/investigate/history        — List past investigations.
  GET  /api/investigate/<id>           — Get single investigation details.
  PATCH /api/investigate/<id>          — Update analyst status + notes.
  DELETE /api/investigate/<id>         — Delete an investigation.
  GET  /api/investigate/<id>/export/md   — Export as Markdown.
  GET  /api/investigate/<id>/export/json — Export as JSON.
  GET  /api/investigate/<id>/export/rule/<sigma|yara> — Export detection rule.
"""

import json
import logging

from flask import jsonify, redirect, render_template, request, Response, session

from config import MAX_ANALYST_NOTES_CHARS, MAX_HISTORY_ROWS
from extensions import (
    app,
    limiter,
    csrf_protect,
    login_required,
    get_user_id,
    get_user_id_int,
)
from utils.sanitize import sanitize_artifact_meta
from services.cyberguru_agent import investigate, result_from_db_row
from services.db_service import (
    get_investigation_history,
    get_investigation_by_id,
    delete_investigation,
    update_investigation_analyst,
)
from services.triage_service import SUPPORTED_ARTIFACT_TYPES, SUPPORTED_SEVERITIES, SUPPORTED_VERDICTS
from utils.defang import defang_iocs
from utils.confidence import compute_confidence_detail
from utils.rule_generator import generate_sigma_rule, generate_yara_rule

logger = logging.getLogger(__name__)


# Analyst triage workflow states. Distinct from severity (which is a risk
# measure produced by the pipeline) — these reflect where the case sits in
# the analyst's review process.
ANALYST_STATUSES = ["New", "In Review", "Resolved", "False Positive", "Escalated"]


INVESTIGATION_TYPES = [
    {"id": "auto",           "icon": "🔍", "label": "Auto Investigation",      "desc": "Let AI detect the artifact type automatically"},
    {"id": "url",            "icon": "🔗", "label": "URL Analysis",            "desc": "Analyze a suspicious URL or web address"},
    {"id": "phishing_email", "icon": "📧", "label": "Email Analysis",          "desc": "Inspect email headers and content for phishing"},
    {"id": "log",            "icon": "📋", "label": "Log Analysis",            "desc": "Parse security logs and event data"},
    {"id": "malware",        "icon": "🦠", "label": "Malware Analysis",        "desc": "Analyze malware reports and behavior descriptions"},
    {"id": "ioc",            "icon": "🎯", "label": "IOC Analysis",            "desc": "Analyze hashes, IPs, domains, and URLs"},
    {"id": "domain",         "icon": "🌐", "label": "Domain Analysis",         "desc": "Investigate domain reputation and DNS records"},
    {"id": "ip",             "icon": "📡", "label": "IP Analysis",             "desc": "Check IP reputation across threat intel feeds"},
]

_UI_TYPE_IDS = {item["id"] for item in INVESTIGATION_TYPES}

# Defensive consistency check: the UI and the service must agree on the
# supported artifact types. A mismatch is a programming error, not user input.
if _UI_TYPE_IDS != set(SUPPORTED_ARTIFACT_TYPES):
    raise RuntimeError("INVESTIGATION_TYPES and SUPPORTED_ARTIFACT_TYPES diverged")


@app.route("/", methods=["GET"])
@limiter.limit("60 per minute")
def home():
    """Smart root — landing page for anonymous visitors, the Investigation
    Center for authenticated users."""
    if session.get("user"):
        return render_template("investigate.html", types=INVESTIGATION_TYPES)
    return render_template("index.html")


@app.route("/investigate", methods=["GET"])
@limiter.limit("60 per minute")
def investigate_page():
    """Serve the Investigation Center page. Anonymous visitors are sent to
    the landing page (which links to Google login)."""
    if not session.get("user"):
        return redirect("/")
    return render_template("investigate.html", types=INVESTIGATION_TYPES)


@app.route("/api/investigate/analyze", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_user_id)
@login_required
@csrf_protect
def investigate_analyze():
    """Run the full investigation pipeline and return structured results.

    Request body:
      { "artifact": "...", "type": "auto|url|phishing_email|log|malware|ioc|domain|ip" }

    The response always includes a truthful ``status``:
      completed — valid assessment, all executed stages succeeded
      partial   — valid assessment, but an optional stage/provider failed
      failed    — no valid AI assessment; deterministic data is still returned

    A failed assessment is still HTTP 200 for client compatibility, but it is
    explicitly marked and never presented as a low-risk result.
    """
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400

        raw_artifact = data.get("artifact", "")
        if not isinstance(raw_artifact, str):
            return jsonify({"error": "artifact must be a string."}), 400

        artifact, artifact_truncated = sanitize_artifact_meta(raw_artifact)
        if not artifact:
            return jsonify({"error": "Please provide an artifact to investigate."}), 400

        raw_type = data.get("type", "auto")
        if raw_type is None:
            raw_type = "auto"
        if not isinstance(raw_type, str):
            return jsonify({"error": "type must be a string."}), 400
        artifact_type = raw_type.strip().lower() or "auto"
        if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
            return jsonify({"error": "Unsupported investigation type."}), 400

        user_id = get_user_id_int()
        result = investigate(artifact, user_id=user_id, artifact_type=artifact_type)

        analysis = result.get("analysis") or {}
        analysis_valid = bool(result.get("analysis_valid"))
        iocs = result.get("iocs") or {}
        threat_intel = result.get("threat_intel") or {}
        mitre_techniques = result.get("mitre_techniques") or []
        mitre = result.get("mitre")
        report = result.get("report") or ""
        confidence = result.get("confidence") or 0
        verdict = analysis.get("verdict") if analysis_valid else None
        severity = analysis.get("severity") if analysis_valid else None
        total_iocs = _count_iocs(iocs)

        return jsonify({
            "status": result.get("status", "failed"),
            "analysis_valid": analysis_valid,
            "from_cache": bool(result.get("from_cache")),
            "artifact_type": result.get("artifact_type", artifact_type),
            "artifact_truncated": artifact_truncated,
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "analysis": {
                "verdict": verdict,
                "severity": severity,
                "summary": analysis.get("analysis") or analysis.get("summary") or "",
                "valid": analysis_valid,
                "status": analysis.get("status", "error"),
                "error_code": analysis.get("error_code"),
                "narrative_available": bool(analysis.get("analysis") or analysis.get("summary")),
            },
            "analysis_error": result.get("analysis_error") if not analysis_valid else None,
            "threat_intel": threat_intel,
            "mitre": mitre,
            "mitre_techniques": mitre_techniques,
            "evidence": result.get("evidence", []),
            "recommendations": result.get("recommendations", []),
            "report": report,
            "risk": {
                "score": _risk_score(severity, total_iocs, analysis_valid),
                "severity": severity or "unknown",
                "confidence": confidence if analysis_valid else 0,
                "confidence_factors": result.get("confidence_factors", []),
                "assessed": analysis_valid,
                "threat_category": _classify_threat(verdict, severity, mitre_techniques),
                "ioc_count": total_iocs,
            },
            "pipeline": result.get("pipeline", []),
            "analyst_status": result.get("analyst_status") or "New",
            "analyst_notes": result.get("analyst_notes") or "",
            "investigation_id": result.get("investigation_id"),
        })

    except Exception:
        logger.exception("Investigation analysis failed")
        return jsonify({"error": "Analysis failed. Please try again."}), 500


def _risk_score(severity, ioc_count, analysis_valid):
    """Severity-derived score, only for a validated assessment."""
    if not analysis_valid:
        return 0
    severity_scores = {"critical": 90, "high": 70, "medium": 50, "low": 20}
    base_score = severity_scores.get(severity or "", 0)
    if ioc_count > 5:
        base_score = min(100, base_score + 10)
    return min(100, base_score)


def _detail_confidence_factors(result, iocs):
    """Confidence factors for a stored investigation.

    The analyze response records factors at run time; the detail response
    reconstructs them from the stored inputs.  The heuristic is
    deterministic, so a recomputed score equal to the stored score means
    the factors genuinely explain it.  Any mismatch (legacy rows, changed
    inputs) reports factors as unavailable instead of inventing an
    explanation that does not match the displayed score.
    """
    if not result.get("analysis_valid"):
        return ["Assessment invalid — confidence not computed."]
    stored = result.get("confidence") or 0
    detail = compute_confidence_detail(
        verdict=result.get("analysis", {}).get("verdict"),
        severity=result.get("analysis", {}).get("severity"),
        threat_intel=result.get("threat_intel") or {},
        mitre_techniques=result.get("mitre_techniques") or [],
        iocs=iocs or {},
    )
    if detail.get("score") == stored:
        return detail.get("factors") or []
    return [
        "Confidence factors were not recorded for this stored investigation "
        "and do not match the current heuristic inputs."
    ]


def _classify_threat(verdict, severity, mitre_techniques):
    """Derive a threat category, or 'Unassessed' when there is no assessment."""
    if verdict not in SUPPORTED_VERDICTS or severity not in SUPPORTED_SEVERITIES:
        return "Unassessed"
    mitre_techniques = mitre_techniques if isinstance(mitre_techniques, list) else []
    if severity == "critical" or verdict == "likely_malicious":
        for technique in mitre_techniques:
            name = (technique.get("name") or "").lower()
            if "ransomware" in name or "impact" in name:
                return "Ransomware / Malware"
            if "phishing" in name:
                return "Phishing / Social Engineering"
            if "credential" in name or "brute" in name:
                return "Credential Attack"
            if "command" in name or "execution" in name:
                return "Malicious Execution"
        return "Suspicious Activity"
    if verdict == "suspicious":
        return "Anomalous Behavior"
    if verdict == "benign":
        return "Benign"
    return "Inconclusive"


# ── History & Detail endpoints ──────────────────────────────────────────────


@app.route("/api/investigate/history", methods=["GET"])
@limiter.limit("30 per minute", key_func=get_user_id)
@login_required
def investigate_history():
    """Return the user's investigation history (summaries)."""
    try:
        user_id = get_user_id_int()
        limit = request.args.get("limit", 50, type=int)
        if limit is None:
            limit = 50
        limit = max(1, min(limit, MAX_HISTORY_ROWS))
        history = get_investigation_history(user_id, limit=limit) or []
        rows = []
        for row in history:
            rows.append({
                "id": row["id"],
                "verdict": row.get("verdict"),
                "severity": row.get("severity"),
                "confidence": row.get("confidence") or 0,
                "analysis_valid": row.get("analysis_valid"),
                "artifact_type": row.get("artifact_type"),
                "analyst_status": row.get("analyst_status") or "New",
                "analyst_notes": row.get("analyst_notes"),
                "mitre_id": row.get("mitre_id"),
                "mitre_name": row.get("mitre_name"),
                "ioc_count": _count_iocs(row.get("iocs")),
                "created_at": _iso(row.get("created_at")),
            })
        return jsonify({"history": rows})
    except Exception:
        logger.exception("Error fetching investigation history")
        return jsonify({"error": "Could not load history."}), 500


@app.route("/api/investigate/<int:investigation_id>", methods=["GET"])
@limiter.limit("30 per minute", key_func=get_user_id)
@login_required
def investigate_detail(investigation_id):
    """Return full details for a single investigation."""
    try:
        user_id = get_user_id_int()
        row = get_investigation_by_id(investigation_id, user_id)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404

        # Reconstruct the SAME contract a fresh/cached investigation returns,
        # so a stored result cannot silently lose its verdict, evidence,
        # narrative, or truthful pipeline outcomes.
        result = result_from_db_row(row)
        iocs = result.get("iocs") or {}
        return jsonify({
            "id": row["id"],
            "status": result.get("status"),
            "artifact_type": result.get("artifact_type"),
            "verdict": result.get("analysis", {}).get("verdict"),
            "severity": result.get("analysis", {}).get("severity"),
            "confidence": result.get("confidence"),
            "analysis_valid": result.get("analysis_valid"),
            "analysis_error": result.get("analysis_error"),
            "analysis": result.get("analysis"),
            "risk": {
                "score": _risk_score(
                    result.get("analysis", {}).get("severity"),
                    _count_iocs(iocs),
                    result.get("analysis_valid"),
                ),
                "severity": result.get("analysis", {}).get("severity") or "unknown",
                "confidence": result.get("confidence"),
                "confidence_factors": _detail_confidence_factors(result, iocs),
                "assessed": result.get("analysis_valid"),
                "threat_category": _classify_threat(
                    result.get("analysis", {}).get("verdict"),
                    result.get("analysis", {}).get("severity"),
                    result.get("mitre_techniques"),
                ),
                "ioc_count": _count_iocs(iocs),
            },
            "evidence": result.get("evidence", []),
            "recommendations": result.get("recommendations", []),
            "analyst_status": result.get("analyst_status"),
            "analyst_notes": result.get("analyst_notes"),
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "threat_intel": result.get("threat_intel"),
            "mitre": result.get("mitre"),
            "mitre_techniques": result.get("mitre_techniques", []),
            "report": result.get("report"),
            "pipeline": result.get("pipeline", []),
            "ioc_count": _count_iocs(iocs),
            "created_at": _iso(row.get("created_at")),
        })
    except Exception:
        logger.exception("Error fetching investigation detail")
        return jsonify({"error": "Could not load investigation."}), 500


@app.route("/api/investigate/<int:investigation_id>", methods=["DELETE"])
@limiter.limit("20 per minute", key_func=get_user_id)
@login_required
@csrf_protect
def investigate_delete(investigation_id):
    """Delete a single investigation."""
    try:
        user_id = get_user_id_int()
        deleted = delete_investigation(investigation_id, user_id)
        if not deleted:
            return jsonify({"error": "Investigation not found."}), 404
        return jsonify({"ok": True})
    except Exception:
        logger.exception("Error deleting investigation")
        return jsonify({"error": "Could not delete investigation."}), 500


@app.route("/api/investigate/<int:investigation_id>", methods=["PATCH"])
@limiter.limit("30 per minute", key_func=get_user_id)
@login_required
@csrf_protect
def investigate_update_analyst(investigation_id):
    """Update analyst workflow state for an investigation.

    Request:  { "status": "In Review" | "New" | "Resolved" | "False Positive" | "Escalated",
                "notes": "<optional analyst note>" }

    Omitting ``notes`` preserves the stored note; sending an empty string
    clears it explicitly.
    """
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400

        status = data.get("status")
        if not isinstance(status, str) or not status.strip():
            return jsonify({"error": "status is required."}), 400
        status = status.strip()
        if status not in ANALYST_STATUSES:
            return jsonify({"error": "Unknown status."}), 400

        notes_provided = "notes" in data
        notes = data.get("notes")
        if notes is not None and not isinstance(notes, str):
            return jsonify({"error": "notes must be a string."}), 400
        if notes is not None:
            notes = notes.strip()
            if len(notes) > MAX_ANALYST_NOTES_CHARS:
                return jsonify({"error": "notes is too long."}), 400
        if not notes_provided:
            notes = None

        user_id = get_user_id_int()
        row = update_investigation_analyst(investigation_id, user_id, status, notes)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404

        return jsonify({
            "ok": True,
            "id": row["id"],
            "analyst_status": row.get("analyst_status"),
            "analyst_notes": row.get("analyst_notes"),
        })
    except Exception:
        logger.exception("Error updating investigation analyst state")
        return jsonify({"error": "Could not update investigation."}), 500


# ── Export endpoints ────────────────────────────────────────────────────────


@app.route("/api/investigate/<int:investigation_id>/export/md", methods=["GET"])
@limiter.limit("20 per minute", key_func=get_user_id)
@login_required
def export_investigation_md(investigation_id):
    """Export investigation as Markdown."""
    try:
        user_id = get_user_id_int()
        row = get_investigation_by_id(investigation_id, user_id)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404

        analysis_valid = _row_analysis_valid(row)
        verdict = row.get("verdict") if analysis_valid else "unavailable"
        severity = row.get("severity") if analysis_valid else "unavailable"
        confidence = (row.get("confidence") or 0) if analysis_valid else 0
        report = _text(row.get("report"))
        reconstructed = result_from_db_row(row)
        pipeline = reconstructed.get("pipeline") or []
        pipeline_summary = "; ".join(
            f"{stage.get('label', stage.get('name', 'stage'))}: {stage.get('status', 'unknown')}"
            for stage in pipeline
        ) or "N/A"
        analyst_status = row.get("analyst_status") or "New"

        md = f"""# Investigation Report

**Verdict:** {verdict}
**Severity:** {severity}
**Confidence:** {confidence}/100 (heuristic — not a calibrated probability)
**Assessment valid:** {"yes" if analysis_valid else "no"}
**MITRE ATT&CK:** {row.get("mitre_id", "N/A")} - {row.get("mitre_name", "N/A")}
**Analyst status:** {analyst_status}
**Pipeline:** {pipeline_summary}
**Date:** {_iso(row.get("created_at")) or "N/A"}

---

{report}
"""
        return Response(
            md,
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=investigation-{investigation_id}.md"}
        )
    except Exception:
        logger.exception("Error exporting markdown")
        return jsonify({"error": "Could not export report."}), 500


@app.route("/api/investigate/<int:investigation_id>/export/json", methods=["GET"])
@limiter.limit("20 per minute", key_func=get_user_id)
@login_required
def export_investigation_json(investigation_id):
    """Export investigation as JSON."""
    try:
        user_id = get_user_id_int()
        row = get_investigation_by_id(investigation_id, user_id)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404
        iocs = row.get("iocs") if isinstance(row.get("iocs"), dict) else {}
        threat_intel = row.get("threat_intel") if isinstance(row.get("threat_intel"), dict) else {}
        analysis_valid = _row_analysis_valid(row)
        reconstructed = result_from_db_row(row)

        export = {
            "id": row["id"],
            "status": "completed" if analysis_valid else "failed",
            "artifact_type": row.get("artifact_type") or "auto",
            "verdict": row.get("verdict") if analysis_valid else None,
            "severity": row.get("severity") if analysis_valid else None,
            "confidence": (row.get("confidence") or 0) if analysis_valid else 0,
            "analysis_valid": analysis_valid,
            "mitre": {"id": row.get("mitre_id"), "name": row.get("mitre_name")},
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "threat_intel": threat_intel,
            "recommendations": reconstructed.get("recommendations", []),
            "pipeline": reconstructed.get("pipeline", []),
            "analyst_status": row.get("analyst_status") or "New",
            "analyst_notes": row.get("analyst_notes") or "",
            "report": _text(row.get("report")),
            "analysis_text": _text(row.get("analysis_text")),
            "created_at": _iso(row.get("created_at")),
        }
        return Response(
            json.dumps(export, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=investigation-{investigation_id}.json"}
        )
    except Exception:
        logger.exception("Error exporting JSON")
        return jsonify({"error": "Could not export report."}), 500


@app.route("/api/investigate/<int:investigation_id>/export/rule/<rule_format>", methods=["GET"])
@limiter.limit("20 per minute", key_func=get_user_id)
@login_required
def export_investigation_rule(investigation_id, rule_format):
    """Export a detection rule (Sigma or YARA) for the investigation."""
    try:
        if rule_format not in ("sigma", "yara"):
            return jsonify({"error": "Unknown rule format."}), 400

        user_id = get_user_id_int()
        row = get_investigation_by_id(investigation_id, user_id)
        if not row:
            return jsonify({"error": "Investigation not found."}), 404

        if rule_format == "sigma":
            body = generate_sigma_rule(row)
            mimetype = "text/yaml"
            filename = f"cyberguru-sigma-{investigation_id}.yml"
        else:
            body = generate_yara_rule(row)
            mimetype = "text/x-yara"
            filename = f"cyberguru-yara-{investigation_id}.yar"

        return Response(
            body,
            mimetype=mimetype,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception:
        logger.exception("Error exporting detection rule")
        return jsonify({"error": "Could not export rule."}), 500


def _row_analysis_valid(row):
    """Infer validity for legacy rows that predate ``analysis_valid``."""
    stored = row.get("analysis_valid")
    if stored is not None:
        return bool(stored)
    return bool(
        not row.get("analysis_error")
        and row.get("verdict") in SUPPORTED_VERDICTS
        and row.get("severity") in SUPPORTED_SEVERITIES
    )


def _iso(value):
    if value is None:
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


def _text(value):
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _count_iocs(iocs):
    if not isinstance(iocs, dict):
        return 0
    total = 0
    for key in ("ips", "domains", "urls", "hashes", "emails"):
        values = iocs.get(key)
        if isinstance(values, list):
            total += len(values)
    return total
