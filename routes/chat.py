import json
import requests
from flask import jsonify, request, Response, stream_with_context

from extensions import app, limiter, csrf_protect, login_required, get_user_id, jdump
from config import API_URL, API_URL_STREAM, SYSTEM_INSTRUCTION, GENERATION_CONFIG, GOOGLE_SEARCH_TOOL
from services.gemini_service import gemini_post, build_contents, GeminiRateLimitError, GeminiServiceError
from utils.sanitize import sanitize_input, validate_history
from utils.grounding import needs_grounding
from utils.quiz import sanitize_quiz_topic, build_quiz_prompt
from services.cyberguru_agent import investigate

# ==========================
# CHAT ROUTE (non-streaming, kept for fallback)
# ==========================

@app.route("/chat", methods=["POST"])
@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def chat():
    try:
        data = request.get_json()
        user_message = sanitize_input(data.get("message", ""))
        history       = validate_history(data.get("history", []))

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400
        # CyberGuru Agent Mode
        if user_message.lower().startswith("/investigate"):

            artifact = user_message[len("/investigate"):].strip()

            result = investigate(artifact)

            return jsonify({
                "reply": result["report"]
            })

        quiz_mode = False
        quiz_topic = ""
        if user_message.lower().startswith("/quiz"):
            quiz_mode = True
            quiz_topic = user_message[5:].strip()

        if quiz_mode:
            if not quiz_topic:
                return jsonify({
                    "reply": "⚠️ Please provide a topic.\n\nExample:\n/quiz sql injection"
                })
            safe_topic = sanitize_quiz_topic(quiz_topic)
            if not safe_topic:
                return jsonify({
                    "reply": (
                        "⚠️ That topic isn't in the quiz library.\n\n"
                        "Try one of: SQL Injection, XSS, Malware, Phishing, "
                        "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                        "Buffer Overflow, Social Engineering, or another cybersecurity topic."
                    )
                })
            user_message = build_quiz_prompt(safe_topic)

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

        if needs_grounding(user_message):
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        response = gemini_post(API_URL, payload, timeout=30)
        response_data = response.json()
        bot_reply = response_data["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"reply": bot_reply})

    except GeminiRateLimitError:
        return jsonify({"reply": "⚠️ Gemini rate limit reached. Please wait a moment and try again."}), 429
    except GeminiServiceError as e:
        return jsonify({"reply": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}), 503
    except requests.exceptions.Timeout:
        return jsonify({"reply": "⚠️ Request timed out."}), 500
    except requests.exceptions.RequestException:
        return jsonify({"reply": "⚠️ Unable to reach Gemini API."}), 500
    except KeyError:
        return jsonify({"reply": "⚠️ Unexpected response format from Gemini API."}), 500
    except Exception as e:
        print("GEMINI ERROR:", e)
        print(f"UNHANDLED ERROR [/chat]: {e}")
        return jsonify({"reply": "⚠️ An internal server error occurred. Please try again."}), 500


# ==========================
# STREAMING CHAT ROUTE
# ==========================

@app.route("/chat-stream", methods=["POST"])

@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def chat_stream():
    
    try:
        data = request.get_json()
        user_message = sanitize_input(data.get("message", ""))
        history      = validate_history(data.get("history", []))

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400
        if user_message.lower().startswith("/investigate"):

            print("🔥 STREAM INVESTIGATE HIT 🔥")
            artifact = user_message[len("/investigate"):].strip()

            result = investigate(artifact)

            print("RESULT =", result)
            def agent_response():

                analysis = result.get("analysis", {})
                iocs = result.get("iocs", {})
                mitre = result.get("mitre", {})
                report = result.get("report", "")

                reply = f"""
            🛡️ CyberGuru Investigation

            Verdict: {analysis.get('verdict', 'unknown')}
            Severity: {analysis.get('severity', 'unknown')}

            📌 MITRE ATT&CK
            {mitre.get('id', 'N/A')} - {mitre.get('name', 'N/A')}

            🌐 IPs
            {', '.join(iocs.get('ips', [])) or 'None'}

            🔗 URLs
            {', '.join(iocs.get('urls', [])) or 'None'}

            📧 Emails
            {', '.join(iocs.get('emails', [])) or 'None'}

            📋 Report

            {report}
            """
                threat_intel = result.get("threat_intel", {})

                reply += "\n🌐 Threat Intelligence\n"

                for item in threat_intel.get("abuseipdb", []):

                    if "result" in item:
                        reply += f"\nAbuseIPDB: {item['ip']}"

                    elif "error" in item:
                        reply += f"\nAbuseIPDB Error: {item['error']}"

                for item in threat_intel.get("virustotal", []):

                    if "result" in item:
                        reply += f"\nVirusTotal: {item['ip']}"

                    elif "error" in item:
                        reply += f"\nVirusTotal Error: {item['error']}"
                    yield (
                    "data: "
                    + jdump({"token": reply})
                    + "\n\n"
                ).encode("utf-8")

                yield (
                    "data: "
                    + jdump({"done": True})
                    + "\n\n"
                ).encode("utf-8")

            return Response(
                stream_with_context(agent_response()),
                content_type="text/event-stream; charset=utf-8"
            )
        # ── Quiz mode (mirrors /chat handling) ──
        if user_message.lower().startswith("/quiz"):
            quiz_topic = user_message[5:].strip()
            if not quiz_topic:
                def no_topic():
                    yield ("data: " + jdump({"token": "⚠️ Please provide a topic.\n\nExample:\n`/quiz sql injection`"}) + "\n\n").encode("utf-8")
                    yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")
                return Response(stream_with_context(no_topic()), content_type="text/event-stream; charset=utf-8")
            safe_topic = sanitize_quiz_topic(quiz_topic)
            if not safe_topic:
                def bad_topic():
                    msg = (
                        "⚠️ That topic isn't in the quiz library.\n\n"
                        "Try one of: SQL Injection, XSS, Malware, Phishing, "
                        "Network Security, Cryptography, Ransomware, OWASP Top 10, "
                        "Buffer Overflow, Social Engineering, or another cybersecurity topic."
                    )
                    yield ("data: " + jdump({"token": msg}) + "\n\n").encode("utf-8")
                    yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")
                return Response(stream_with_context(bad_topic()), content_type="text/event-stream; charset=utf-8")
            user_message = build_quiz_prompt(safe_topic)

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": build_contents(history, user_message),
            "generationConfig": GENERATION_CONFIG
        }

        use_grounding = needs_grounding(user_message)
        if use_grounding:
            payload["tools"] = [GOOGLE_SEARCH_TOOL]

        gemini_resp = gemini_post(API_URL_STREAM, payload, stream=True, timeout=60)

        def generate():
            grounding_meta = None

            if use_grounding:
                yield ("data: " + jdump({"status": "searching"}) + "\n\n").encode("utf-8")

            for raw_line_bytes in gemini_resp.iter_lines():
                raw_line = raw_line_bytes.decode("utf-8") if isinstance(raw_line_bytes, bytes) else raw_line_bytes
                if not raw_line:
                    continue
                if raw_line.startswith("data:"):
                    json_str = raw_line[5:].strip()
                    if json_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(json_str)
                        candidate = chunk.get("candidates", [{}])[0]

                        text_piece = (
                            candidate.get("content", {})
                                     .get("parts", [{}])[0]
                                     .get("text", "")
                        )
                        if text_piece:
                            yield ("data: " + jdump({"token": text_piece}) + "\n\n").encode("utf-8")

                        if "groundingMetadata" in candidate:
                            grounding_meta = candidate["groundingMetadata"]

                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue

            if grounding_meta:
                sources = []
                for chunk in grounding_meta.get("groundingChunks", []):
                    web = chunk.get("web", {})
                    if web.get("uri") and web.get("title"):
                        sources.append({
                            "title": web["title"],
                            "uri":   web["uri"],
                        })
                queries = grounding_meta.get("webSearchQueries", [])
                rendered = grounding_meta.get("searchEntryPoint", {}).get("renderedContent", "")
                if sources or rendered:
                    yield ("data: " + jdump({
                        "grounding": {
                            "sources":  sources,
                            "queries":  queries,
                            "rendered": rendered,
                        }
                    }) + "\n\n").encode("utf-8")

            yield ("data: " + jdump({"done": True}) + "\n\n").encode("utf-8")

        return Response(
            stream_with_context(generate()),
            content_type="text/event-stream; charset=utf-8",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )

    except GeminiRateLimitError:
        def rate_err():
            yield ("data: " + jdump({"rate_limited": True, "retry_after": 60, "error": "⚠️ Gemini rate limit reached after retries. Please wait a minute and try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(rate_err()), content_type="text/event-stream; charset=utf-8")

    except GeminiServiceError as e:
        def svc_err():
            yield ("data: " + jdump({"error": f"⚠️ Gemini service error ({e.status_code}). Please try again shortly."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(svc_err()), content_type="text/event-stream; charset=utf-8")

    except requests.exceptions.Timeout:
        def timeout_err():
            yield ("data: " + jdump({"error": "⚠️ Request timed out."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(timeout_err()), content_type="text/event-stream; charset=utf-8")

    except Exception as e:
        def general_err():
            print(f"UNHANDLED ERROR [stream]: {e}")
            yield ("data: " + jdump({"error": "⚠️ An internal server error occurred. Please try again."}) + "\n\n").encode("utf-8")
        return Response(stream_with_context(general_err()), content_type="text/event-stream; charset=utf-8")
