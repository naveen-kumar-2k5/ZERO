"""Entry point. Wires the Flask app from src/ and runs it."""
import os

from dotenv import load_dotenv
from pathlib import Path

# Load .env from the directory containing app.py
load_dotenv(Path(__file__).resolve().parent / ".env")

import urllib3
from flask import Flask

from src.config import SECRET_KEY, APP_ENV, MISSING_PROD_SECRETS
from src.routes import register_blueprints
from src.agents_sync import start_agent_sync_thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fail fast in production if secrets are missing
if APP_ENV == "production" and MISSING_PROD_SECRETS:
    raise RuntimeError(f"missing required secrets in production: {MISSING_PROD_SECRETS}")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    # Optional blueprint from app_vuln (kept at project root)
    try:
        from app_vuln import vuln_bp
        app.register_blueprint(vuln_bp)
    except ImportError:
        pass

    register_blueprints(app)

    # Start background Wazuh -> agents sync
    start_agent_sync_thread()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)