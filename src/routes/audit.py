"""Audit log API."""
from datetime import timezone, timedelta

from flask import Blueprint, jsonify, request

from ..db import get_conn
from ..helpers import login_required


bp = Blueprint("audit", __name__)


@bp.route("/api/v1/audit", methods=["GET"])
@login_required
def api_audit_list():
    q     = (request.args.get("q") or "").strip()
    actor = (request.args.get("actor") or "").strip()
    try:
        limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
    except ValueError:
        limit = 200

    where, params = [], []
    if q:
        like = f"%{q}%"
        where.append("(action ILIKE %s OR coalesce(ref,'') ILIKE %s OR coalesce(detail,'') ILIKE %s)")
        params.extend([like, like, like])
    if actor:
        where.append("actor = %s")
        params.append(actor)

    sql = """
        SELECT id, action, ref, detail, actor, created_at
        FROM audit_log
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
    """.format(where=("WHERE " + " AND ".join(where)) if where else "")
    params.append(limit)

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = [{
        "id":         r["id"],
        "action":     r["action"],
        "ref":        r["ref"],
        "detail":     r["detail"],
        "actor":      r["actor"],
        "createdAt":  r["created_at"].isoformat(),
        "createdAtIst": r["created_at"].astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ).strftime("%d %b %Y, %H:%M IST"),
    } for r in rows]

    return jsonify({"status": "success", "count": len(data), "data": data})