"""Environment-driven configuration and shared constants."""
import os

APP_ENV = os.getenv("APP_ENV", "development")

# ── Flask ─────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-secret-key-change-me")

# ── Database ──────────────────────────────────────────
DB_CONFIG = {
    "dbname":   os.getenv("PG_DB",       "zerorespong_db"),
    "user":     os.getenv("PG_USER",     "zero"),
    "password": os.getenv("PG_PASSWORD", ""),
    "host":     os.getenv("PG_HOST",     "localhost"),
    "port":     os.getenv("PG_PORT",     "5432"),
}

# ── External services ─────────────────────────────────
WEBHOOK_URL      = os.getenv("WEBHOOK_URL",      "http://127.0.0.1:5000")
UI_URL           = os.getenv("UI_URL",           "http://127.0.0.1:5001")
POLLER_STALE_SEC = int(os.getenv("POLLER_STALE_SEC", "300"))

WAZUH_HOST = os.getenv("WAZUH_HOST", "https://192.168.244.131:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")

# ── Background sync ───────────────────────────────────
AGENT_SYNC_INTERVAL_SEC = int(os.getenv("AGENT_SYNC_INTERVAL_SEC", "300"))

# ── Production safety check ───────────────────────────
MISSING_PROD_SECRETS = [
    k for k in ("SECRET_KEY", "WAZUH_PASS", "PG_PASSWORD") if not os.getenv(k)
]

# ── Password hashing ──────────────────────────────────
PBKDF2_ITERATIONS = 600_000
PBKDF2_PREFIX     = "pbkdf2_sha256"