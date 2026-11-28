"""Attack analysis aggregate."""
from datetime import datetime, timezone, timedelta

from flask import Blueprint, jsonify, request

from ..db import get_conn
from ..helpers import login_required, classify_category, row_to_alert


bp = Blueprint("analysis", __name__)


THREAT_LABELS = {
    "bf":  "Brute Force",
    "pe":  "Privilege Escalation",
    "fim": "File Integrity",
    "ra":  "Ransomware",
}


@bp.route("/api/v1/analysis", methods=["GET"])
@login_required
def api_analysis():
    try:
        days = min(max(int(request.args.get("days", 14)), 1), 30)
    except ValueError:
        days = 14

    detail_type = (request.args.get("type") or "bf").lower()
    if detail_type not in THREAT_LABELS:
        detail_type = "bf"

    now = datetime.now(timezone.utc)
    start_of_window = (now - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, agent, agent_ip, description, level, mitre_id,
                    rule_id, source_ip, target_user, threat_type, time
                FROM alerts
                ORDER BY time DESC NULLS LAST, id DESC
            """)
            all_rows = cur.fetchall()

            cur.execute("""
                WITH days AS (
                    SELECT generate_series(
                        date_trunc('day', %s::timestamptz),
                        date_trunc('day', %s::timestamptz),
                        interval '1 day'
                    ) AS day
                )
                SELECT d.day::date AS day FROM days d ORDER BY d.day
            """, (start_of_window, now))
            day_labels = [r["day"] for r in cur.fetchall()]
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    cat_counts  = {"bf": 0, "pe": 0, "fim": 0, "ra": 0}
    cat_agents  = {"bf": {}, "pe": {}, "fim": {}, "ra": {}}
    agent_breakdown = {}
    detail_rows = []
    trend_map = {d: {"bf": 0, "pe": 0, "fim": 0, "ra": 0} for d in day_labels}

    for r in all_rows:
        cat = classify_category(r)
        cat_counts[cat] += 1

        ag = r["agent"] or "unknown"
        cat_agents[cat][ag] = cat_agents[cat].get(ag, 0) + 1
        if ag not in agent_breakdown:
            agent_breakdown[ag] = {"bf": 0, "pe": 0, "fim": 0, "ra": 0}
        agent_breakdown[ag][cat] += 1

        ts = r["time"]
        if ts:
            day = ts.date()
            if day in trend_map:
                trend_map[day][cat] += 1

        if cat == detail_type:
            detail_rows.append(row_to_alert(r))

    total_alerts = sum(cat_counts.values())

    cards = []
    for key, label in THREAT_LABELS.items():
        n = cat_counts[key]
        pct = round((n / total_alerts) * 100) if total_alerts else 0
        top_agents = sorted(cat_agents[key].items(), key=lambda kv: kv[1], reverse=True)[:3]
        cards.append({
            "key":       key,
            "label":     label,
            "count":     n,
            "pct":       pct,
            "topAgents": [{"agent": a, "count": c} for a, c in top_agents],
        })

    trend = [{"date": d.isoformat(), **trend_map[d]} for d in day_labels]

    targets = sorted(agent_breakdown.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:6]
    targets_out = [{"agent": a, "count": sum(b.values()), "breakdown": b} for a, b in targets]

    return jsonify({
        "status":      "success",
        "window":      {"days": days, "from": start_of_window.isoformat()},
        "generated":   now.isoformat(),
        "totalAlerts": total_alerts,
        "cards":       cards,
        "trend":       trend,
        "targets":     targets_out,
        "detailType":  detail_type,
        "detailCount": len(detail_rows),
        "detail":      detail_rows[:20],
    })