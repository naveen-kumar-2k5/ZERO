"""Alerts feed, dashboard aggregates, and Wazuh passthrough."""
from datetime import datetime, timezone, timedelta

import requests
from flask import Blueprint, jsonify, request

from ..config import WAZUH_HOST
from ..db import get_conn
from ..helpers import (
    login_required, row_to_alert, classify_category,
)
from ..wazuh import get_wazuh_token, wazuh_get


bp = Blueprint("alerts", __name__)


@bp.route("/api/v1/alerts/feed")
@login_required
def alerts_feed():
    sev      = request.args.get("sev") or None
    category = request.args.get("category") or None
    q        = (request.args.get("q") or "").strip()
    from_s   = (request.args.get("from") or "").strip() or None
    to_s     = (request.args.get("to")   or "").strip() or None

    try:
        limit = min(max(int(request.args.get("limit", 500)), 1), 2000)
    except ValueError:
        limit = 500

    where, params = [], []

    if from_s:
        try:
            where.append("time >= %s")
            params.append(datetime.fromisoformat(from_s.replace("Z", "+00:00")))
        except ValueError:
            return jsonify({"status": "error", "error": f"invalid 'from' timestamp: {from_s}"}), 400

    if to_s:
        try:
            where.append("time <= %s")
            params.append(datetime.fromisoformat(to_s.replace("Z", "+00:00")))
        except ValueError:
            return jsonify({"status": "error", "error": f"invalid 'to' timestamp: {to_s}"}), 400

    if sev in ("critical", "high", "medium", "low"):
        ranges = {"critical": (16, 999), "high": (14, 15),
                  "medium": (12, 13), "low": (0, 11)}
        lo, hi = ranges[sev]
        where.append("level BETWEEN %s AND %s")
        params.extend([lo, hi])

    if q:
        where.append(
            "(description ILIKE %s OR agent ILIKE %s "
            "OR source_ip ILIKE %s OR target_user ILIKE %s)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like])

    sql = """
        SELECT id, agent, agent_ip, description, level, mitre_id, rule_id,
            source_ip, target_user, threat_type, time
        FROM alerts
        {where}
        ORDER BY time DESC NULLS LAST, id DESC
        LIMIT %s
    """.format(where=("WHERE " + " AND ".join(where)) if where else "")
    params.append(limit)

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = [row_to_alert(r) for r in rows]
    if category:
        data = [a for a in data if a["category"] == category]

    return jsonify({
        "status": "success",
        "count":  len(data),
        "range":  {"from": from_s, "to": to_s},
        "data":   data,
    })


@bp.route("/api/v1/dashboard")
@login_required
def api_dashboard():
    try:
        days = min(max(int(request.args.get("days", 7)), 1), 30)
    except ValueError:
        days = 7

    now = datetime.now(timezone.utc)
    start_of_window = (now - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT
                    count(*)                                              AS total,
                    count(*) FILTER (WHERE level > 15)                    AS critical,
                    count(*) FILTER (WHERE level BETWEEN 14 AND 15)       AS high,
                    count(*) FILTER (WHERE level BETWEEN 12 AND 13)       AS medium,
                    count(*) FILTER (WHERE level BETWEEN 0 AND 11)        AS low,
                    count(*) FILTER (WHERE time > now() - interval '24 hours') AS last24h
                FROM alerts
            """)
            stats = dict(cur.fetchone())

            severity = [
                {"key": "critical", "count": stats["critical"]},
                {"key": "high",     "count": stats["high"]},
                {"key": "medium",   "count": stats["medium"]},
                {"key": "low",      "count": stats["low"]},
            ]

            cur.execute("""
                WITH days AS (
                    SELECT generate_series(
                        date_trunc('day', %s::timestamptz),
                        date_trunc('day', %s::timestamptz),
                        interval '1 day'
                    ) AS day
                )
                SELECT
                    d.day::date                          AS day,
                    coalesce(a.total, 0)                 AS total,
                    coalesce(a.critical, 0)              AS critical
                FROM days d
                LEFT JOIN (
                    SELECT
                        date_trunc('day', time)::date AS day,
                        count(*)                      AS total,
                        count(*) FILTER (WHERE level > 15) AS critical
                    FROM alerts
                    WHERE time >= %s
                    GROUP BY 1
                ) a ON a.day = d.day
                ORDER BY d.day
            """, (start_of_window, now, start_of_window))
            trend = [
                {"date": r["day"].isoformat(),
                 "total": r["total"],
                 "critical": r["critical"]}
                for r in cur.fetchall()
            ]

            cur.execute("""
                SELECT threat_type, mitre_id, count(*) AS count
                FROM alerts
                GROUP BY threat_type, mitre_id
            """)
            cat_counts = {"bf": 0, "pe": 0, "fim": 0, "ra": 0}
            for r in cur.fetchall():
                cat = classify_category(r)
                cat_counts[cat] += int(r["count"])
            categories = [{"key": k, "count": v} for k, v in cat_counts.items()]

            cur.execute("""
                SELECT coalesce(agent, 'unknown') AS agent, count(*) AS count
                FROM alerts
                GROUP BY 1
                ORDER BY count DESC
                LIMIT 6
            """)
            top_agents = [{"agent": r["agent"], "count": int(r["count"])}
                          for r in cur.fetchall()]

            cur.execute("""
                SELECT source_ip, count(*) AS count
                FROM alerts
                WHERE source_ip IS NOT NULL
                AND source_ip <> 'N/A'
                AND source_ip <> 'unknown'
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 6
            """)
            top_ips = [{"ip": r["source_ip"], "count": int(r["count"])}
                       for r in cur.fetchall()]

            cur.execute("""
                SELECT id, agent, agent_ip, description, level, mitre_id,
                    rule_id, source_ip, target_user, threat_type, time
                FROM alerts
                ORDER BY time DESC NULLS LAST, id DESC
                LIMIT 8
            """)
            recent = [row_to_alert(r) for r in cur.fetchall()]
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({
        "status":    "success",
        "window":    {"days": days, "from": start_of_window.isoformat()},
        "generated": now.isoformat(),
        "stats":     stats,
        "severity":  severity,
        "categories": categories,
        "trend":     trend,
        "top_agents": top_agents,
        "top_ips":   top_ips,
        "recent":    recent,
    })


@bp.route("/api/agents")
@login_required
def api_agents():
    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 500
    try:
        r = requests.get(
            f"{WAZUH_HOST}/agents",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=8,
        )
        if r.status_code != 200:
            return jsonify({"error": f"Wazuh API error: {r.text[:200]}"}), r.status_code
        items = r.json().get("data", {}).get("affected_items", [])
        return jsonify([
            {"id": a.get("id"), "name": a.get("name"), "status": a.get("status")}
            for a in items
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/alerts")
@login_required
def api_alerts():
    try:
        payload = wazuh_get("/alerts", {"limit": 10, "sort": "-timestamp"})
        return jsonify(payload.get("data", {}).get("affected_items", []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500