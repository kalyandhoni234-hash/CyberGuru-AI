"""
Investigation Center — Dedicated SOC workspace for artifact analysis.

Endpoints:
  GET  /                               — Smart root: landing page when logged out,
                                         Investigation Center when authenticated.
  GET  /investigate                    — Serve the Investigation Center page (gated).
  POST /api/investigate/analyze        — Run full investigation pipeline.
  GET  /api/investigate/history        — List past investigations.
  GET  /api/investigate/<id>           — Get single investigation details.
  DELETE /api/investigate/<id>         — Delete an investigation.
  GET  /api/investigate/<id>/export/md   — Export as Markdown.
  GET  /api/investigate/<id>/export/json — Export as JSON.

Reuses existing:
  - services/cyberguru_agent.investigate()
  - services/triage_service.analyze_artifact()
  - services/db_service (investigation CRUD)
  - utils/* (IOC, threat intel, MITRE, report, defang, cache)
"""

import json
import logging

from flask import jsonify, redirect, render_template, request, Response, session
from extensions import app, limiter, csrf_protect, login_required, get_user_id, get_user_id_int
from utils.sanitize import sanitize_artifact
from services.cyberguru_agent import investigate
from services.db_service import (
    get_investigation_history,
    get_investigation_by_id,
    delete_investigation,
    update_investigation_analyst,
)
from utils.defang import defang_iocs
from utils.evidence import build_evidence
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

    Returns JSON with:
      - iocs (extracted indicators)
      - analysis (AI analysis with verdict/severity)
      - threat_intel (AbuseIPDB, VirusTotal results)
      - mitre_techniques (MITRE ATT&CK mappings)
      - report (full incident report text)
      - risk (risk score assessment)
      - pipeline (step-by-step progress)
    """
    try:
        data = request.get_json(silent=True) or {}
        artifact = sanitize_artifact(data.get("artifact", ""))

        if not artifact:
            return jsonify({"error": "Please provide an artifact to investigate."}), 400

        user_id = get_user_id_int()

        result = investigate(artifact, user_id=user_id)

        analysis = result.get("analysis", {})
        iocs = result.get("iocs", {})
        threat_intel = result.get("threat_intel", {})
        mitre_techniques = result.get("mitre_techniques", [])
        mitre = result.get("mitre")
        report = result.get("report", "")
        from_cache = result.get("from_cache", False)

        verdict = analysis.get("verdict", "inconclusive")
        severity = analysis.get("severity", "low")

        # Risk scoring — risk.score is severity-driven (the gauge); confidence
        # is a separate, evidence-strength score computed by the pipeline.
        severity_scores = {"critical": 90, "high": 70, "medium": 50, "low": 20, "unknown": 0}
        base_score = severity_scores.get(severity, 0)
        total_iocs = len(iocs.get("ips", [])) + len(iocs.get("domains", [])) + len(iocs.get("urls", [])) + len(iocs.get("hashes", [])) + len(iocs.get("emails", []))
        if total_iocs > 5:
            base_score = min(100, base_score + 10)
        risk_score = min(100, base_score)
        confidence = result.get("confidence", 0)

        threat_category = _classify_threat(verdict, severity, mitre_techniques)

        # Build pipeline steps summary
        pipeline_steps = [
            {"step": 1, "label": "Extracting Indicators",       "status": "done"},
            {"step": 2, "label": "Parsing Evidence",            "status": "done"},
            {"step": 3, "label": "Threat Intelligence Lookup",  "status": "done"},
            {"step": 4, "label": "MITRE ATT&CK Mapping",        "status": "done"},
            {"step": 5, "label": "Risk Assessment",             "status": "done"},
            {"step": 6, "label": "AI Analysis",                 "status": "done"},
            {"step": 7, "label": "Report Generation",           "status": "done"},
        ]

        return jsonify({
            "status": "completed",
            "from_cache": from_cache,
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "analysis": {
                "verdict": verdict,
                "severity": severity,
                "summary": analysis.get("analysis", ""),
            },
            "threat_intel": threat_intel,
            "mitre": mitre,
            "mitre_techniques": mitre_techniques,
            "evidence": result.get("evidence", []),
            "report": report,
            "risk": {
                "score": risk_score,
                "severity": severity,
                "confidence": confidence,
                "threat_category": threat_category,
                "ioc_count": total_iocs,
            },
            "pipeline": pipeline_steps,
            "analyst_status": "New",
            "analyst_notes": "",
            "investigation_id": result.get("investigation_id"),
        })

    except Exception:
        logger.exception("Investigation analysis failed")
        return jsonify({"error": "Analysis failed. Please try again."}), 500


def _classify_threat(verdict: str, severity: str, mitre_techniques: list) -> str:
    """Derive a threat category from verdict, severity and MITRE techniques."""
    if severity == "critical" or verdict == "likely_malicious":
        for t in mitre_techniques:
            name = (t.get("name") or "").lower()
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
        history = get_investigation_history(user_id, limit=limit) or []
        rows = []
        for row in history:
            rows.append({
                "id": row["id"],
                "verdict": row.get("verdict"),
                "severity": row.get("severity"),
                "confidence": row.get("confidence") or 0,
                "analyst_status": row.get("analyst_status") or "New",
                "analyst_notes": row.get("analyst_notes"),
                "mitre_id": row.get("mitre_id"),
                "mitre_name": row.get("mitre_name"),
                "ioc_count": _count_iocs(row.get("iocs")),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
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

        mitre = None
        if row.get("mitre_id"):
            mitre = {"id": row["mitre_id"], "name": row.get("mitre_name")}

        iocs = row.get("iocs") or {}
        threat_intel = row.get("threat_intel") or {}
        report = row.get("report", "")
        verdict = row.get("verdict", "inconclusive")
        severity = row.get("severity", "low")
        confidence = row.get("confidence") or 0

        total_iocs = _count_iocs(iocs)

        mitre_techniques = [mitre] if mitre else []
        evidence = build_evidence(
            iocs=iocs,
            threat_intel=threat_intel,
            mitre_techniques=mitre_techniques,
        )

        return jsonify({
            "id": row["id"],
            "verdict": verdict,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "analyst_status": row.get("analyst_status") or "New",
            "analyst_notes": row.get("analyst_notes"),
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "threat_intel": threat_intel,
            "mitre": mitre,
            "report": report,
            "ioc_count": total_iocs,
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
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
    Response: the updated investigation summary.
    """
    try:
        data = request.get_json(silent=True) or {}
        status = (data.get("status") or "").strip()
        notes = data.get("notes")

        if not status:
            return jsonify({"error": "status is required."}), 400
        if status not in ANALYST_STATUSES:
            return jsonify({"error": "Unknown status."}), 400
        if notes is not None and not isinstance(notes, str):
            return jsonify({"error": "notes must be a string."}), 400
        notes = (notes or "").strip()

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

        report = row.get("report", "")
        md = f"""# Investigation Report

**Verdict:** {row.get("verdict", "N/A")}
**Severity:** {row.get("severity", "N/A")}
**MITRE ATT&CK:** {row.get("mitre_id", "N/A")} - {row.get("mitre_name", "N/A")}
**Date:** {row.get("created_at").isoformat() if row.get("created_at") else "N/A"}

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
        iocs = row.get("iocs") or {}
        threat_intel = row.get("threat_intel") or {}

        export = {
            "id": row["id"],
            "verdict": row.get("verdict"),
            "severity": row.get("severity"),
            "mitre": {"id": row.get("mitre_id"), "name": row.get("mitre_name")},
            "iocs": iocs,
            "iocs_defanged": defang_iocs(iocs),
            "threat_intel": threat_intel,
            "report": row.get("report", ""),
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
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


def _count_iocs(iocs) -> int:
    if not iocs:
        return 0
    return sum(len(iocs.get(k) or []) for k in ("ips", "domains", "urls", "hashes", "emails"))
