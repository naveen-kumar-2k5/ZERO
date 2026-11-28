"""Authentication routes and current-user injection."""
from flask import Blueprint, jsonify, render_template, request, session, redirect, url_for

from ..db import get_conn
from ..security import hash_password, verify_password
from ..helpers import audit


bp = Blueprint("auth", __name__)


@bp.app_context_processor
def inject_current_user():
    uid = session.get("user_id")
    if not uid:
        return {"current_user": None}
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, display_name, email, role "
                "FROM users WHERE id = %s AND status = 'active'",
                (uid,),
            )
            r = cur.fetchone()
    except Exception:
        return {"current_user": None}

    if not r:
        session.clear()
        return {"current_user": None}

    return {"current_user": {
        "id":          r["id"],
        "username":    r["username"],
        "displayName": r["display_name"],
        "email":       r["email"],
        "role":        r["role"],
    }}


@bp.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("pages.dashboard"))
    return render_template("login.html")


@bp.route("/api/v1/auth/login", methods=["POST"])
def api_auth_login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "error": "username and password are required"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, display_name, email, password_hash, role, status "
                "FROM users WHERE lower(username) = %s",
                (username,),
            )
            row = cur.fetchone()

            if not row:
                return jsonify({"status": "error", "error": "invalid username or password"}), 401
            ok, needs_rehash = verify_password(password, row["password_hash"])
            if not ok:
                return jsonify({"status": "error", "error": "invalid username or password"}), 401
            if row["status"] != "active":
                return jsonify({"status": "error", "error": "account is disabled"}), 403

            if needs_rehash:
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (hash_password(password), row["id"]),
                )

            cur.execute("UPDATE users SET last_login = now() WHERE id = %s", (row["id"],))
            audit(cur, "Login", row["username"], "Successful sign-in", actor=row["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    session.clear()
    session.permanent = True
    session["user_id"]      = row["id"]
    session["role"]         = row["role"]
    session["username"]     = row["username"]
    session["display_name"] = row["display_name"]

    return jsonify({
        "status": "success",
        "data": {
            "id":          row["id"],
            "username":    row["username"],
            "displayName": row["display_name"],
            "email":       row["email"],
            "role":        row["role"],
        },
    })


@bp.route("/logout")
def logout_page():
    username = session.get("username")
    session.clear()
    if username:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                audit(cur, "Logout", username, "Signed out", actor=username)
        except Exception:
            pass
    return redirect(url_for("auth.login_page"))


@bp.route("/api/v1/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
    return jsonify({"status": "success"})


@bp.route("/api/v1/me/reset-password", methods=["POST"])
def api_me_reset_password():
    if "user_id" not in session:
        return jsonify({"status": "error", "error": "not authenticated"}), 401

    body = request.get_json(silent=True) or {}
    current = body.get("currentPassword") or ""
    new     = body.get("newPassword") or ""
    confirm = body.get("confirmPassword") or ""

    if not current or not new or not confirm:
        return jsonify({"status": "error", "error": "all fields are required"}), 400
    if new != confirm:
        return jsonify({"status": "error", "error": "new passwords do not match"}), 400
    if len(new) < 8:
        return jsonify({"status": "error", "error": "password must be at least 8 characters"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
            row = cur.fetchone()
            ok, _ = verify_password(current, row["password_hash"]) if row else (False, False)
            if not ok:
                return jsonify({"status": "error", "error": "current password is incorrect"}), 401

            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (hash_password(new), session["user_id"]),
            )
            audit(cur, "Password reset", session["username"],
                  "User reset their own password", actor=session["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success"})