from dotenv import load_dotenv
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests


print("RUNNING FILE:", __file__)
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
You are CyberGuru AI, an expert cybersecurity mentor.

Rules:

1. Answer only cybersecurity-related questions.

2. For unrelated questions, reply:
"I am CyberGuru AI and can only assist with cybersecurity topics."
 but for general questions like hi,how are you you to reply in soft tone

3. Explain concepts in a beginner-friendly way.

4. Structure answers using:
   - Definition
   - Example
   - Why it matters
   - Prevention/Mitigation

5. Use bullet points when possible.

6. For tools, commands, or code:
   - Explain what each part does.
   - Mention risks if applicable.

7. Never encourage illegal hacking,
   unauthorized access,
   malware deployment,
   credential theft,
   or harmful activities.

8. When discussing offensive security,
   focus on education,
   defense,
   detection,
   and ethical use.

9. Keep responses concise unless the user asks for details.

10. Use emojis occasionally:
🛡️ 🔍 ⚠️ ✅
"""

# ==========================
# HEALTH CHECK ROUTE
# ==========================


from flask import Flask, send_from_directory, jsonify


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ==========================
# CHAT ROUTE
# ==========================

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        user_message = data.get("message", "").strip()

        # Validate empty message
        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        payload = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_INSTRUCTION}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_message}]
                }
            ]
        }

        response = requests.post(
            API_URL,
            json=payload,
            timeout=30
        )

        print("Status Code:", response.status_code)
        print("Response:", response.text)

        try:
            response.raise_for_status()

        except requests.exceptions.HTTPError:

            if response.status_code == 429:
                return jsonify({
                    "reply": "⚠️ Gemini rate limit reached. Please wait a minute and try again."
                })

            elif response.status_code >= 500:
                return jsonify({
                    "reply": "⚠️ Gemini service is currently unavailable."
                })

            return jsonify({
                "reply": "⚠️ An unexpected API error occurred."
            })

        response_data = response.json()

        bot_reply = (
            response_data["candidates"][0]
            ["content"]["parts"][0]["text"]
        )

        return jsonify({"reply": bot_reply})

    except requests.exceptions.Timeout:
        return jsonify({"reply": "Request timed out."}), 500

    except requests.exceptions.RequestException:
        return jsonify({"reply": "⚠️ Unable to reach Gemini API."}), 500

    except KeyError:
        return jsonify({"reply": "Unexpected response format from Gemini API."}), 500

    except Exception as e:
        return jsonify({"reply": f"Server Error: {str(e)}"}), 500


# ==========================
# ANALYZE FILE ROUTE
# ==========================

@app.route("/analyze-file", methods=["POST"])
def analyze_file():
    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return jsonify({"reply": "No file uploaded."}), 400

    try:
        print("FILE NAME:", uploaded_file.filename)
        content = uploaded_file.read().decode("utf-8")
        print("CONTENT:", repr(content))

        # Send file content to Gemini for cybersecurity analysis
        payload = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_INSTRUCTION}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                f"Analyze the following file content for cybersecurity issues, "
                                f"vulnerabilities, or suspicious patterns. "
                                f"File name: {uploaded_file.filename}\n\n"
                                f"File content:\n{content}"
                            )
                        }
                    ]
                }
            ]
        }

        response = requests.post(
            API_URL,
            json=payload,
            timeout=30
        )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            if response.status_code == 429:
                return jsonify({
                    "reply": "⚠️ Gemini rate limit reached. Please wait a minute and try again."
                })
            elif response.status_code >= 500:
                return jsonify({
                    "reply": "⚠️ Gemini service is currently unavailable."
                })
            return jsonify({"reply": "⚠️ An unexpected API error occurred."})

        response_data = response.json()

        bot_reply = (
            response_data["candidates"][0]
            ["content"]["parts"][0]["text"]
        )

        return jsonify({"reply": bot_reply})

    except UnicodeDecodeError:
        return jsonify({
            "reply": "⚠️ Could not read file. Only plain text files (e.g. .txt, .py, .js, .log) are supported."
        }), 400

    except Exception as e:
        return jsonify({"reply": f"Error reading file: {str(e)}"}), 500


# ==========================
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False  # Set to True only during local development
    )