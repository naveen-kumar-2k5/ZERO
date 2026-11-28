"""Metrics API (real DB numbers + demo placeholders for MTTD/MTTR)."""
from datetime import datetime, timezone, timedelta

from flask import Blueprint, jsonify

from ..db import get_conn
from ..helpers import login_required, classify_category


bp = Blueprint("metrics", __name__)


@bp.route("/api/v1/metrics", methods=["GET"])
@login_required
def api_metrics():
    now = datetime.now(timezone.utc)
    start_of_window = (now - timedelta(days=6)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) AS total,
                    count(*) FILTER (WHERE time > now() - interval '24 hours') AS last24h
                FROM alerts
            """)
            alert_stats = dict(cur.fetchone())

            cur.execute("""
                SELECT count(*) AS total,
                    count(*) FILTER (WHERE status NOT IN ('resolved','false-positive')) AS open,
                    count(*) FILTER (WHERE status = 'resolved') AS resolved
                FROM cases
            """)
            case_stats = dict(cur.fetchone())

            cur.execute("SELECT count(*) AS n FROM reports")
            reports_n = int(cur.fetchone()["n"])

            cur.execute("""
                WITH days AS (
                    SELECT generate_series(
                        date_trunc('day', %s::timestamptz),
                        date_trunc('day', now()),
                        interval '1 day'
                    ) AS day
                )
                SELECT d.day::date AS day, coalesce(a.n, 0) AS total
                FROM days d
                LEFT JOIN (
                    SELECT date_trunc('day', time)::date AS day, count(*) AS n
                    FROM alerts WHERE time >= %s
                    GROUP BY 1
                ) a ON a.day = d.day
                ORDER BY d.day
            """, (start_of_window, start_of_window))
            weekly_trend = [
                {"date": r["day"].isoformat(), "total": int(r["total"])}
                for r in cur.fetchall()
            ]

            cur.execute("""
                SELECT threat_type, mitre_id, count(*) AS count
                FROM alerts
                WHERE time >= %s
                GROUP BY threat_type, mitre_id
            """, (start_of_window,))
            cat_counts = {"bf": 0, "pe": 0, "fim": 0, "ra": 0}
            for r in cur.fetchall():
                cat = classify_category(r)
                cat_counts[cat] += int(r["count"])
            per_category = [{"key": k, "count": v} for k, v in cat_counts.items()]
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    demo_mttd = 4.2
    demo_mttr = 22.0
    demo_fp_pct = 12.0

    monthly = [
        {"month": "Apr", "total": 8,  "bf": 4, "pe": 1, "fim": 2, "ra": 1},
        {"month": "May", "total": 12, "bf": 6, "pe": 2, "fim": 3, "ra": 1},
        {"month": "Jun", "total": 7,  "bf": 3, "pe": 1, "fim": 2, "ra": 1},
        {"month": "Jul", "total": 15, "bf": 8, "pe": 2, "fim": 3, "ra": 2},
        {"month": "Aug", "total": 11, "bf": 5, "pe": 2, "fim": 3, "ra": 1},
        {"month": "Sep", "total": 8,  "bf": 4, "pe": 1, "fim": 2, "ra": 1},
    ]

    trend_30 = []
    for i in range(30):
        d = (now - timedelta(days=29 - i)).date()
        mttd = round(6.1 - i * 0.06, 1)
        mttr = round(35.0 - i * 0.43, 1)
        trend_30.append({"date": d.isoformat(), "mttdMinutes": mttd, "mttrMinutes": mttr})

    fpr_30 = []
    for i in range(30):
        d = (now - timedelta(days=29 - i)).date()
        if i < 8:
            pct = round(28 - i * 0.5, 1)
        else:
            pct = round(max(10, 18 - (i - 8) * 0.45), 1)
        fpr_30.append({"date": d.isoformat(), "pct": pct})

    return jsonify({
        "status":     "success",
        "generated":  now.isoformat(),
        "real": {
            "totalAlerts":      int(alert_stats["total"]),
            "alertsLast24h":    int(alert_stats["last24h"]),
            "totalCases":       int(case_stats["total"]),
            "openCases":        int(case_stats["open"]),
            "resolvedCases":    int(case_stats["resolved"]),
            "reportsGenerated": reports_n,
            "perCategory7d":    per_category,
            "weeklyTrend":      weekly_trend,
        },
        "demo": {
            "mttdMinutes":       demo_mttd,
            "mttrMinutes":       demo_mttr,
            "falsePositivePct":  demo_fp_pct,
            "monthly":           monthly,
            "trend30":           trend_30,
            "fpr30":             fpr_30,
        },
        "disclaimer": "MTTD, MTTR, false-positive rate, and monthly history are demo placeholders. "
                      "Real alert counts, cases, and reports come from the live database.",
    })