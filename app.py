from dotenv import load_dotenv
load_dotenv()  # load .env before ANY os.getenv() call

from extensions import app  # noqa: E402  (must come after load_dotenv)
from services.db_service import init_db  # noqa: E402

init_db()

# Import route modules to register their @app.route handlers
from routes import auth, analyze, misc, triage, investigate_center, seo  # noqa: F401,E402

# ==========================
# START SERVER
# ==========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )