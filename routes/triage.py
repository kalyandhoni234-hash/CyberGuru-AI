"""
Cybersecurity Triage Routes
API endpoints for security artifact analysis using Gemini Managed Agent
Follows CyberGuru's patterns: rate limiting, CSRF, auth, error handling
"""

import json
from flask import jsonify, request

from extensions import app, limiter, csrf_protect, login_required, get_user_id, jdump
from services.triage_service import (
    analyze_artifact,
    analyze_log,
    analyze_email,
    analyze_malware,
    check_interaction_status
)


# ==========================
# TRIAGE API ENDPOINTS
# ==========================

@app.route("/api/triage/analyze", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze():
    """
    Analyze a security artifact (auto-detect type or specify)
    
    Request:
    {
        "artifact": "log content / email / malware report",
        "type": "auto | log | phishing_email | malware | url"
    }
    
    Response:
    {
        "verdict": "benign | suspicious | likely_malicious | inconclusive",
        "severity": "low | medium | high | critical",
        "analysis": "full agent analysis text",
        "interaction_id": "gemini-interaction-id",
        "status": "completed"
    }
    """
    try:
        data = request.get_json()
        artifact = data.get('artifact', '').strip()
        artifact_type = data.get('type', 'auto')
        
        if not artifact:
            return jsonify({'error': 'artifact field is required'}), 400
        
        result = analyze_artifact(artifact, artifact_type)
        
        if result.get('status') == 'error':
            return jsonify(result), 500
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"TRIAGE ERROR [/api/triage/analyze]: {e}")
        return jsonify({'error': str(e), 'message': 'Analysis failed'}), 500


@app.route("/api/triage/analyze-log", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_log():
    """
    Analyze a log file for security threats
    
    Request:
    {
        "log": "log file content"
    }
    """
    try:
        data = request.get_json()
        log_content = data.get('log', '').strip()
        
        if not log_content:
            return jsonify({'error': 'log field is required'}), 400
        
        result = analyze_log(log_content)
        
        if result.get('status') == 'error':
            return jsonify(result), 500
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"TRIAGE ERROR [/api/triage/analyze-log]: {e}")
        return jsonify({'error': str(e), 'message': 'Log analysis failed'}), 500


@app.route("/api/triage/analyze-email", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_email():
    """
    Analyze an email for phishing/security threats
    
    Request:
    {
        "email": "email body content",
        "subject": "email subject (optional)",
        "from": "sender address (optional)",
        "urls": ["url1", "url2"] (optional)
    }
    """
    try:
        data = request.get_json()
        email_content = data.get('email', '').strip()
        
        if not email_content:
            return jsonify({'error': 'email field is required'}), 400
        
        result = analyze_email(
            email_content,
            subject=data.get('subject'),
            sender=data.get('from'),
            urls=data.get('urls', [])
        )
        
        if result.get('status') == 'error':
            return jsonify(result), 500
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"TRIAGE ERROR [/api/triage/analyze-email]: {e}")
        return jsonify({'error': str(e), 'message': 'Email analysis failed'}), 500


@app.route("/api/triage/analyze-malware", methods=["POST"])
@limiter.limit("20 per minute; 100 per day", key_func=get_user_id)
@csrf_protect
@login_required
def triage_analyze_malware():
    """
    Analyze a malware behavior report
    
    Request:
    {
        "report": "malware analysis report content"
    }
    """
    try:
        data = request.get_json()
        report = data.get('report', '').strip()
        
        if not report:
            return jsonify({'error': 'report field is required'}), 400
        
        result = analyze_malware(report)
        
        if result.get('status') == 'error':
            return jsonify(result), 500
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"TRIAGE ERROR [/api/triage/analyze-malware]: {e}")
        return jsonify({'error': str(e), 'message': 'Malware analysis failed'}), 500


@app.route("/api/triage/status/<interaction_id>", methods=["GET"])
@limiter.limit("30 per minute", key_func=get_user_id)
@login_required
def triage_status(interaction_id):
    """
    Check the status of an ongoing analysis
    
    Returns the analysis result when completed
    """
    try:
        result = check_interaction_status(interaction_id)
        
        if result.get('status') == 'error':
            return jsonify(result), 404
        
        return jsonify(result), 200
    
    except Exception as e:
        print(f"TRIAGE ERROR [/api/triage/status]: {e}")
        return jsonify({'error': str(e)}), 500


@app.route("/api/triage/info", methods=["GET"])
def triage_info():
    """
    Get information about available triage endpoints
    (No auth required - informational endpoint)
    """
    return jsonify({
        "name": "🔴 Cybersecurity Triage Agent",
        "description": "AI-powered security artifact analysis",
        "status": "ready",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/triage/analyze",
                "description": "Analyze any security artifact (auto-detect type)",
                "requires_auth": True
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-log",
                "description": "Analyze a log file for threats",
                "requires_auth": True
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-email",
                "description": "Analyze an email for phishing",
                "requires_auth": True
            },
            {
                "method": "POST",
                "path": "/api/triage/analyze-malware",
                "description": "Analyze malware behavior",
                "requires_auth": True
            },
            {
                "method": "GET",
                "path": "/api/triage/status/<interaction_id>",
                "description": "Check analysis status",
                "requires_auth": True
            }
        ],
        "rate_limits": {
            "analyze_endpoints": "20 per minute, 100 per day",
            "status_check": "30 per minute"
        }
    }), 200