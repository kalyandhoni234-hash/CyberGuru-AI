from dotenv import load_dotenv
load_dotenv()  # load .env before ANY os.getenv() call

print("RUNNING FILE:", __file__)

from extensions import app  # noqa: E402  (must come after load_dotenv)
from services.db_service import init_db

init_db()

# Import route modules to register their @app.route handlers
from routes import auth, chat, analyze, misc, triage, news ,tts , ctf  # add news # noqa: F401,E402
# ↑ Added 'triage' to import the new security triage agent routes

# ==========================
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )