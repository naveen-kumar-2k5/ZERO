"""Background Wazuh -> agents table sync thread."""
import os
import threading
import time

from .config import AGENT_SYNC_INTERVAL_SEC
from .db import get_conn
from .wazuh import wazuh_get


def _sync_agents_once() -> None:
    """Upsert name/os/ip from Wazuh. Never touches secret_env_var, port or protected on existing rows."""
    try:
        wazuh = wazuh_get("/agents", {"limit": 500})
    except Exception as e:
        print(f"[agents-sync] Wazuh unreachable: {e}")
        return

    items = wazuh.get("data", {}).get("affected_items", [])
    inserted = updated = 0
    try:
        with get_conn() as conn, conn.cursor() as cur:
            for a in items:
                name = a.get("name")
                ip   = a.get("ip")
                os_platform = ((a.get("os") or {}).get("platform") or "").lower()
                os_kind = "windows" if "windows" in os_platform else "linux"
                if not name or not ip:
                    continue
                secret_env = "ZR_SECRET_" + name.upper().replace("-", "_")
                cur.execute("""
                    INSERT INTO agents (name, os, ip, port, secret_env_var)
                    VALUES (%s, %s, %s, 5055, %s)
                    ON CONFLICT (name) DO UPDATE
                      SET ip = EXCLUDED.ip, os = EXCLUDED.os, updated_at = now()
                    RETURNING (xmax = 0) AS inserted
                """, (name, os_kind, ip, secret_env))
                if cur.fetchone()["inserted"]:
                    inserted += 1
                else:
                    updated += 1
    except Exception as e:
        print(f"[agents-sync] DB error: {e}")
        return

    print(f"[agents-sync] {inserted} inserted, {updated} updated")


def _agent_sync_loop() -> None:
    if os.getenv("AGENT_SYNC_DISABLED") == "1":
        print("[agents-sync] disabled via AGENT_SYNC_DISABLED=1")
        return
    time.sleep(5)
    while True:
        try:
            _sync_agents_once()
        except Exception as e:
            print(f"[agents-sync] unexpected: {e}")
        time.sleep(AGENT_SYNC_INTERVAL_SEC)


def start_agent_sync_thread() -> None:
    threading.Thread(
        target=_agent_sync_loop, daemon=True, name="agents-sync"
    ).start()