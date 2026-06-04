from dotenv import load_dotenv
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

# ==========================
# CONFIGURATION
# ==========================


load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = "gemini-2.5-flash"
if not API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not found")

API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{MODEL}:generateContent?key={API_KEY}"
)

SYSTEM_INSTRUCTION = """
You are CyberGuru AI.

Rules:
1. Keep answers concise.
2. Use short paragraphs.
3. Use emojis occasionally.
4. Avoid markdown symbols like ** or ##.
5. Use simple bullet points.
6. Make responses look like a chat message.
7. Maximum 10-15 lines unless user asks for details.
"""

# ==========================
# HEALTH CHECK ROUTE
# ==========================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "running",
        "message": "Cybersecurity Chatbot Backend is Online"
    })

# ==========================
# CHAT ROUTE
# ==========================

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "reply": "No JSON data received."
            }), 400

        user_message = data.get("message", "").strip()

        if not user_message:
            return jsonify({
                "reply": "Please enter a message."
            }), 400

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": user_message
                        }
                    ]
                }
            ],
            "systemInstruction": {
                "parts": [
                    {
                        "text": SYSTEM_INSTRUCTION
                    }
                ]
            }
        }

        response = requests.post(
            API_URL,
            json=payload,
            timeout=30
        )

        print("Status Code:", response.status_code)
        print("Response:", response.text)

        response.raise_for_status()

        response_data = response.json()

        bot_reply = (
            response_data["candidates"][0]
            ["content"]["parts"][0]["text"]
        )

        return jsonify({
            "reply": bot_reply
        })

    except requests.exceptions.Timeout:
        return jsonify({
            "reply": "Request timed out."
        }), 500

    except requests.exceptions.RequestException as e:
        return jsonify({
            "reply": f"API Request Error: {str(e)}"
        }), 500

    except KeyError:
        return jsonify({
            "reply": "Unexpected response format from Gemini API."
        }), 500

    except Exception as e:
        return jsonify({
            "reply": f"Server Error: {str(e)}"
        }), 500

# ==========================
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )