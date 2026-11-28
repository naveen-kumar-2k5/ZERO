"""Settings + user management."""
import psycopg2.errors
from flask import Blueprint, jsonify, request, session

from ..db import get_conn
from ..helpers import login_required, admin_required, audit
from ..security import hash_password

bp = Blueprint("settings", __name__)


def _get_settings(cur):
    cur.execute("SELECT * FROM settings WHERE id = 1")
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO settings (id) VALUES (1) RETURNING *")
        row = cur.fetchone()
    return {
        "orgName":   row["org_name"],
        "orgType":   row["org_type"],
        "city":      row["city"],
        "state":     row["state"],
        "dpoName":   row["dpo_name"],
        "dpoEmail":  row["dpo_email"],
        "dpoPhone":  row["dpo_phone"],
        "dpdpId":    row["dpdp_id"] or "",
        "autoreport": row["autoreport"],
        "updatedAt": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


@bp.route("/api/v1/settings", methods=["GET"])
@login_required
def api_settings_get():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            s = _get_settings(cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    return jsonify({"status": "success", "data": s})


@bp.route("/api/v1/settings", methods=["PUT"])
@admin_required
def api_settings_update():
    body = request.get_json(silent=True) or {}
    updates, params = [], []
    mapping = {
        "orgName":    "org_name",
        "orgType":    "org_type",
        "city":       "city",
        "state":      "state",
        "dpoName":    "dpo_name",
        "dpoEmail":   "dpo_email",
        "dpoPhone":   "dpo_phone",
        "dpdpId":     "dpdp_id",
        "autoreport": "autoreport",
    }
    for js_key, db_col in mapping.items():
        if js_key in body:
            updates.append(f"{db_col} = %s")
            params.append((body[js_key] or "").strip() or None)

    if not updates:
        return jsonify({"status": "error", "error": "no settings fields provided"}), 400

    updates.append("updated_at = now()")

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(f"UPDATE settings SET {', '.join(updates)} WHERE id = 1", params)
            audit(cur, "Settings updated", "Settings",
                  ", ".join(mapping[k] for k in body if k in mapping),
                  actor="Administrator")
            s = _get_settings(cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": s})


# ── Users ─────────────────────────────────────────────
@bp.route("/api/v1/users", methods=["GET"])
@login_required
def api_users_list():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, display_name, email, role, status, last_login, created_at
                FROM users ORDER BY id
            """)
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = [{
        "id":          r["id"],
        "username":    r["username"],
        "displayName": r["display_name"],
        "email":       r["email"],
        "role":        r["role"],
        "status":      r["status"],
        "lastLogin":   r["last_login"].isoformat() if r["last_login"] else None,
        "createdAt":   r["created_at"].isoformat(),
    } for r in rows]

    return jsonify({"status": "success", "count": len(data), "data": data})


@bp.route("/api/v1/users", methods=["POST"])
@admin_required
def api_users_create():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    display  = (body.get("displayName") or "").strip()
    email    = (body.get("email") or "").strip() or None
    password = body.get("password") or ""
    role     = (body.get("role") or "user").lower()

    if not username or not display or not password:
        return jsonify({"status": "error", "error": "username, displayName, and password are required"}), 400
    if role not in ("admin", "user"):
        return jsonify({"status": "error", "error": "role must be admin or user"}), 400
    if len(password) < 8:
        return jsonify({"status": "error", "error": "password must be at least 8 characters"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, display_name, email, password_hash, role) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING *",
                (username, display, email, hash_password(password), role),
            )
            new = cur.fetchone()
            audit(cur, "User created", new["username"],
                  f"Role: {new['role']}", actor=session["display_name"])
    except psycopg2.errors.UniqueViolation:
        return jsonify({"status": "error", "error": f"username '{username}' already exists"}), 409
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": {
        "id":          new["id"],
        "username":    new["username"],
        "displayName": new["display_name"],
        "email":       new["email"],
        "role":        new["role"],
        "status":      new["status"],
        "lastLogin":   None,
        "createdAt":   new["created_at"].isoformat(),
    }}), 201


@bp.route("/api/v1/users/<int:user_id>", methods=["PATCH"])
@admin_required
def api_users_update(user_id):
    body = request.get_json(silent=True) or {}
    updates, params = [], []

    if "status" in body:
        status = (body["status"] or "").lower()
        if status not in ("active", "disabled"):
            return jsonify({"status": "error", "error": "status must be active or disabled"}), 400
        updates.append("status = %s"); params.append(status)

    if "role" in body:
        role = (body["role"] or "").lower()
        if role not in ("admin", "user"):
            return jsonify({"status": "error", "error": "role must be admin or user"}), 400
        updates.append("role = %s"); params.append(role)

    if not updates:
        return jsonify({"status": "error", "error": "no fields to update"}), 400

    params.append(user_id)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING *", params)
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "error", "error": "user not found"}), 404
            audit(cur, "User updated", row["username"],
                  ", ".join(f"{k}={v}" for k, v in body.items()),
                  actor=session["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success"})