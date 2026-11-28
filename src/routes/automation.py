"""Agent inventory (list + sync)."""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, session

from ..db import get_conn
from ..helpers import login_required, admin_required, audit
from ..wazuh import wazuh_get


bp = Blueprint("automation", __name__)


@bp.route("/api/v1/automation/agents", methods=["GET"])
@login_required
def api_automation_agents():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT name, os, ip, port, last_seen, protected FROM agents ORDER BY name"
            )
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    wazuh_status = {}
    try:
        wazuh = wazuh_get("/agents", {"limit": 500})
        for a in wazuh.get("data", {}).get("affected_items", []):
            wazuh_status[a.get("name")] = a.get("status")
    except Exception:
        pass

    data = []
    for r in rows:
        ls = r["last_seen"]
        age = int((datetime.now(timezone.utc) - ls).total_seconds()) if ls else None
        data.append({
            "name":        r["name"],
            "os":          r["os"],
            "ip":          str(r["ip"]) if r["ip"] else None,
            "port":        r["port"],
            "protected":   r["protected"],
            "lastSeen":    ls.isoformat() if ls else None,
            "lastSeenAge": age,
            "online":      age is not None and age < 300,
            "wazuhStatus": wazuh_status.get(r["name"]),
        })
    return jsonify({"status": "success", "count": len(data), "data": data})


@bp.route("/api/v1/automation/agents/sync", methods=["POST"])
@admin_required
def api_automation_agents_sync():
    try:
        wazuh = wazuh_get("/agents", {"limit": 500})
    except Exception as e:
        return jsonify({"status": "error", "error": f"Wazuh: {e}"}), 502

    items = wazuh.get("data", {}).get("affected_items", [])
    inserted = updated = 0
    try:
        with get_conn() as conn, conn.cursor() as cur:
            for a in items:
                name = a.get("name")
                ip   = a.get("ip")
                os_platform = (a.get("os") or {}).get("platform", "").lower()
                os_kind = "windows" if "windows" in os_platform else "linux"
                if not name or not ip:
                    continue
                secret_env = "ZR_SECRET_" + name.upper().replace("-", "_")
                cur.execute("""
                    INSERT INTO agents (name, os, ip, port, secret_env_var)
                    VALUES (%s, %s, %s, 5055, %s)
                    ON CONFLICT (name) DO UPDATE
                      SET ip = EXCLUDED.ip,
                          os = EXCLUDED.os,
                          updated_at = now()
                    RETURNING (xmax = 0) AS inserted
                """, (name, os_kind, ip, secret_env))
                if cur.fetchone()["inserted"]:
                    inserted += 1
                else:
                    updated += 1
            audit(cur, "Agents synced from Wazuh", "automation",
                  f"inserted={inserted} updated={updated}",
                  actor=session.get("display_name") or "System")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({
        "status": "success",
        "data": {"inserted": inserted, "updated": updated, "total": len(items)},
    })