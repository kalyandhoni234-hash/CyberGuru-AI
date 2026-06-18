import io
import asyncio
import logging
import edge_tts
from flask import request, jsonify, Response
from extensions import app, csrf_protect, limiter, login_required, get_user_id

logger = logging.getLogger(__name__)
MAX_CHARS = 1500

@app.route("/api/tts", methods=["POST"])
@limiter.limit("30 per minute; 200 per day", key_func=get_user_id)
@csrf_protect
@login_required
def text_to_speech():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()[:MAX_CHARS]
    if not text:
        return jsonify({"error": "No text provided."}), 400

    try:
        async def generate():
            buf = io.BytesIO()
            communicate = edge_tts.Communicate(text, voice="en-US-GuyNeural")
            async for chunk in communicate.stream():
                if chunk["type"] == "audio":
                    buf.write(chunk["data"])
            buf.seek(0)
            return buf.read()

        loop = asyncio.new_event_loop()
        audio_bytes = loop.run_until_complete(generate())
        loop.close()
        return Response(
            audio_bytes,
            mimetype="audio/mpeg",
            headers={"Cache-Control": "no-store"}
        )
    except Exception:
        logger.exception("edge-tts generation failed")
        return jsonify({"error": "TTS generation failed."}), 500