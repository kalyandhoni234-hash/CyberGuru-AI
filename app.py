import os

from dotenv import load_dotenv
load_dotenv()  # load .env before ANY os.getenv() call

from extensions import app  # noqa: E402  (must come after load_dotenv)
from services.db_service import init_db  # noqa: E402

init_db()

# Import route modules to register their @app.route handlers
from routes import auth, analyze, misc, triage, investigate_center, seo  # noqa: F401,E402

# ==========================
# START SERVER (dev entrypoint; production runs under Gunicorn)
# ==========================

if __name__ == "__main__":
    app.run(
        # Dev entrypoint only — production binds via Gunicorn on Render.
        host=os.getenv("HOST", "0.0.0.0"),  # nosec B104
        port=int(os.getenv("PORT", "5000")),
        debug=False
    )