"""Playbook library API."""
from flask import Blueprint, jsonify

from ..db import get_conn
from ..helpers import login_required
from ..playbooks import PLAYBOOKS, playbook_description


bp = Blueprint("playbooks_routes", __name__)


@bp.route("/api/v1/playbooks/<key>", methods=["GET"])
@login_required
def api_playbook_get(key):
    pb = PLAYBOOKS.get(key)
    if not pb:
        return jsonify({"status": "error", "error": f"unknown playbook '{key}'"}), 404
    return jsonify({
        "status":     "success",
        "key":        key,
        "name":       pb["name"],
        "steps":      pb["steps"],
        "totalSteps": len(pb["steps"]),
    })


@bp.route("/api/v1/playbooks", methods=["GET"])
@login_required
def api_playbooks_list():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT playbook_key,
                    count(*) FILTER (WHERE status NOT IN ('resolved','false-positive')) AS active_count,
                    count(*) AS total_count
                FROM cases
                WHERE playbook_key IS NOT NULL
                GROUP BY playbook_key
            """)
            counts = {r["playbook_key"]: {
                "active": int(r["active_count"]),
                "total":  int(r["total_count"]),
            } for r in cur.fetchall()}

            cur.execute("""
                SELECT DISTINCT ON (playbook_key)
                    playbook_key, id, case_ref, agent_name, severity
                FROM cases
                WHERE status NOT IN ('resolved','false-positive')
                AND playbook_key IS NOT NULL
                ORDER BY playbook_key, opened_at ASC
            """)
            active_cases = {r["playbook_key"]: {
                "id":       r["id"],
                "caseRef":  r["case_ref"],
                "agent":    r["agent_name"],
                "severity": r["severity"],
            } for r in cur.fetchall()}
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    out = []
    for key, pb in PLAYBOOKS.items():
        c = counts.get(key, {"active": 0, "total": 0})
        out.append({
            "key":         key,
            "name":        pb["name"],
            "description": playbook_description(key),
            "stepCount":   len(pb["steps"]),
            "activeCases": c["active"],
            "totalCases":  c["total"],
            "currentCase": active_cases.get(key),
        })

    return jsonify({"status": "success", "count": len(out), "data": out})