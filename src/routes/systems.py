"""Monitored systems + health checks (includes /healthz and /api/v1/health)."""
import time
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify

from ..config import WEBHOOK_URL, UI_URL, POLLER_STALE_SEC
from ..db import get_conn
from ..helpers import login_required
from ..wazuh import wazuh_get


bp = Blueprint("systems", __name__)


WAZUH_AGENT_GROUP_TO_TYPE = {
    "windows":    "endpoint",
    "linux":      "server",
    "cloud":      "cloud",
    "fileserver": "fileserver",
    "database":   "database",
}
DEFAULT_TYPE = "endpoint"
DEFAULT_TYPE_LBL = {
    "endpoint":   "Windows Endpoint",
    "server":     "Linux Server",
    "cloud":      "Cloud",
    "fileserver": "File Server",
    "database":   "Database Server",
}
DEFAULT_DEPT  = "Unassigned"
ONLINE_STATES = {"active"}


def _classify_agent(agent):
    groups = agent.get("group") or []
    if isinstance(groups, str):
        groups = [groups]
    for g in groups:
        key = str(g).lower()
        for needle, t in WAZUH_AGENT_GROUP_TO_TYPE.items():
            if needle in key:
                return t, DEFAULT_TYPE_LBL[t]

    os_platform = (agent.get("os", {}) or {}).get("platform", "").lower()
    name        = (agent.get("name") or "").lower()
    if "windows" in os_platform:
        return "endpoint", DEFAULT_TYPE_LBL["endpoint"]
    if "db" in name or "postgres" in name or "mysql" in name:
        return "database", DEFAULT_TYPE_LBL["database"]
    if "file" in name:
        return "fileserver", DEFAULT_TYPE_LBL["fileserver"]
    if "aws" in name or "azure" in name or "cloud" in name or "ec2" in name:
        return "cloud", DEFAULT_TYPE_LBL["cloud"]
    return DEFAULT_TYPE, DEFAULT_TYPE_LBL[DEFAULT_TYPE]


def _agent_status(agent):
    s = (agent.get("status") or "").lower()
    if s in ONLINE_STATES:
        return "online"
    if s in ("pending", "never_connected"):
        return "warning"
    return "offline"


def _parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


@bp.route("/api/v1/systems")
@login_required
def api_systems():
    try:
        agents_payload = wazuh_get("/agents", {"limit": 500})
    except Exception as e:
        return jsonify({"status": "error", "error": f"Wazuh agents: {e}"}), 502

    agents = agents_payload.get("data", {}).get("affected_items", [])

    alerts_by_agent = {}
    try:
        alerts_payload = wazuh_get("/alerts", {"limit": 500, "sort": "-timestamp"})
        for a in alerts_payload.get("data", {}).get("affected_items", []):
            ag = (a.get("agent") or {}).get("name")
            if ag:
                alerts_by_agent.setdefault(ag, []).append(a)
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    rows = []

    for agent in agents:
        name             = agent.get("name") or f"agent-{agent.get('id')}"
        type_v, type_lbl = _classify_agent(agent)
        status           = _agent_status(agent)
        os_full          = (agent.get("os", {}) or {}).get("name") or "Unknown OS"

        groups = agent.get("group") or []
        if isinstance(groups, str):
            groups = [groups]
        dept = groups[0].title() if groups else DEFAULT_DEPT

        todays, alerts_today, max_level = alerts_by_agent.get(name, []), 0, 0
        for a in todays:
            ts = _parse_iso(a.get("timestamp"))
            if ts and ts.date() == now.date():
                alerts_today += 1
                lvl = (a.get("rule") or {}).get("level") or 0
                if lvl > max_level:
                    max_level = lvl

        last_log_sec = None
        ka = _parse_iso(agent.get("lastKeepAlive"))
        if ka:
            last_log_sec = int((now - ka).total_seconds())
        elif todays:
            newest = max((_parse_iso(a.get("timestamp")) for a in todays), default=None)
            if newest:
                last_log_sec = int((now - newest).total_seconds())

        rows.append({
            "id":          agent.get("id"),
            "host":        name,
            "ip":          agent.get("ip"),
            "type":        type_v,
            "typeLbl":     type_lbl,
            "os":          os_full,
            "dept":        dept,
            "status":      status,
            "lastLogSec":  last_log_sec,
            "alertsToday": alerts_today,
            "alertMaxLvl": max_level,
        })

    order = {"online": 0, "warning": 1, "offline": 2}
    rows.sort(key=lambda r: (order[r["status"]], -r["alertsToday"], r["host"].lower()))

    return jsonify({
        "status":      "success",
        "count":       len(rows),
        "online":      sum(1 for r in rows if r["status"] == "online"),
        "offline":     sum(1 for r in rows if r["status"] == "offline"),
        "warning":     sum(1 for r in rows if r["status"] == "warning"),
        "alertsToday": sum(r["alertsToday"] for r in rows),
        "data":        rows,
    })


# ── Health ─────────────────────────────────────────────
def _check_http(name, url, path, timeout=3):
    started = time.perf_counter()
    try:
        r = requests.get(url.rstrip("/") + path, timeout=timeout)
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        if r.status_code >= 500:
            return {"name": name, "status": "down",
                    "detail": f"HTTP {r.status_code}", "latency_ms": elapsed}
        try:
            body = r.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("status") in ("error", "fail"):
            return {"name": name, "status": "degraded",
                    "detail": f"Payload status={body['status']}", "latency_ms": elapsed}
        return {"name": name, "status": "ok",
                "detail": f"HTTP {r.status_code}", "latency_ms": elapsed}
    except requests.Timeout:
        return {"name": name, "status": "down", "detail": "timeout", "latency_ms": None}
    except requests.RequestException as e:
        return {"name": name, "status": "down",
                "detail": str(e)[:120], "latency_ms": None}


def _check_db():
    started = time.perf_counter()
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'alerts'
                ) AS has_table
            """)
            has_table = cur.fetchone()["has_table"]
            if not has_table:
                elapsed = round((time.perf_counter() - started) * 1000, 1)
                return {"name": "PostgreSQL", "status": "down",
                        "detail": "connected, but `alerts` table is missing",
                        "latency_ms": elapsed}
            cur.execute("""
                SELECT count(*) AS n, min(time) AS oldest, max(time) AS newest
                FROM alerts
            """)
            r = cur.fetchone()
            n      = r["n"]
            oldest = r["oldest"]
            newest = r["newest"]
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        detail = f"{n} rows"
        if n and newest:
            age = int((datetime.now(newest.tzinfo) - newest).total_seconds())
            detail += f" · newest {age}s ago"
        elif n == 0:
            detail += " (empty)"
        return {
            "name":       "PostgreSQL",
            "status":     "ok",
            "detail":     detail,
            "latency_ms": elapsed,
            "rows":       n,
            "oldest":     oldest.isoformat() if oldest else None,
            "newest":     newest.isoformat() if newest else None,
        }
    except Exception as e:
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        return {"name": "PostgreSQL", "status": "down",
                "detail": str(e)[:160], "latency_ms": elapsed}


def _check_poller():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT max(time) AS newest, count(*) AS n FROM alerts")
            row = cur.fetchone()
            newest = row["newest"]
            n      = row["n"]
    except Exception as e:
        return {"name": "Alert sync", "status": "down",
                "detail": f"cannot read alerts: {str(e)[:120]}",
                "last_seen": None, "stale_sec": None, "rows": None}

    if n == 0:
        return {"name": "Alert sync", "status": "degraded",
                "detail": "no rows in alerts — poller has not written yet",
                "last_seen": None, "stale_sec": None, "rows": 0}
    if newest is None:
        return {"name": "Alert sync", "status": "degraded",
                "detail": f"{n} rows but all have NULL time",
                "last_seen": None, "stale_sec": None, "rows": n}

    age = (datetime.now(newest.tzinfo) - newest).total_seconds()
    if age <= POLLER_STALE_SEC:
        return {"name": "Alert sync", "status": "ok",
                "detail": f"last write {int(age)}s ago ({n} rows total)",
                "last_seen": newest.isoformat(), "stale_sec": int(age), "rows": n}
    mins = int(age // 60)
    return {"name": "Alert sync", "status": "degraded",
            "detail": f"stale — last write {mins}m ago (threshold {POLLER_STALE_SEC}s)",
            "last_seen": newest.isoformat(), "stale_sec": int(age), "rows": n}


@bp.route("/healthz")
def healthz():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 503


@bp.route("/api/v1/health")
@login_required
def api_health():
    checks = [
        _check_http("Webhook API",    WEBHOOK_URL, "/api/v1/alerts"),
        _check_http("UI / Flask app", UI_URL,      "/healthz"),
        _check_db(),
        _check_poller(),
    ]
    overall = "ok"
    if any(c["status"] == "down"     for c in checks): overall = "down"
    elif any(c["status"] == "degraded" for c in checks): overall = "degraded"

    return jsonify({
        "status":     overall,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "checks":     checks,
    })