import os
import time
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras
import requests
import urllib3
from flask import Flask, jsonify, render_template, request, session, redirect, url_for, abort
import hashlib
import secrets
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ─────────────────────────────────────────────────────
# Auth Config (Required for sessions)
# ─────────────────────────────────────────────────────
app.secret_key = os.getenv("SECRET_KEY", "dev-only-secret-key-change-me")

# ─────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────
DB_CONFIG = {
    "dbname":   os.getenv("PG_DB",       "zerorespong_db"),
    "user":     os.getenv("PG_USER",     "zero"),
    "password": os.getenv("PG_PASSWORD", "Zero@post1122"),
    "host":     os.getenv("PG_HOST",     "localhost"),
    "port":     os.getenv("PG_PORT",     "5432"),
}

WEBHOOK_URL      = os.getenv("WEBHOOK_URL",      "http://127.0.0.1:5000")
UI_URL           = os.getenv("UI_URL",           "http://127.0.0.1:5001")
POLLER_STALE_SEC = int(os.getenv("POLLER_STALE_SEC", "300"))

WAZUH_HOST = os.getenv("WAZUH_HOST", "https://192.168.244.131:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "MyS3cr37P450r.*-")


def get_conn():
    """psycopg2 connection. Returns dicts from cursors via RealDictCursor."""
    return psycopg2.connect(cursor_factory=psycopg2.extras.RealDictCursor, **DB_CONFIG)


# ─────────────────────────────────────────────────────
# Auth Helpers & Decorators
# ─────────────────────────────────────────────────────
def _hash_password(plain):
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()

def _verify_password(plain, expected_hash):
    return secrets.compare_digest(_hash_password(plain), expected_hash)

@app.context_processor
def _inject_current_user():
    """Makes `current_user` available in every Jinja template."""
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

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────
# Wazuh helper (single source of truth, token cached)
# ─────────────────────────────────────────────────────
_token_cache = {"token": None, "expires": 0.0}


def get_wazuh_token(force=False):
    now = time.time()
    if not force and _token_cache["token"] and now < _token_cache["expires"]:
        return _token_cache["token"]
    try:
        res = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=8,
        )
        if res.status_code == 200:
            token = res.json().get("data", {}).get("token")
            if token:
                _token_cache["token"]   = token
                _token_cache["expires"] = now + 240
                return token
        print(f"[wazuh] auth failed: {res.status_code} - {res.text[:200]}")
        return None
    except Exception as e:
        print(f"[wazuh] auth exception: {e}")
        return None


def _wazuh_headers():
    tok = get_wazuh_token()
    if not tok:
        raise RuntimeError("Wazuh authentication failed")
    return {"Authorization": f"Bearer {tok}"}


def _wazuh_get(path, params=None, timeout=8):
    headers = _wazuh_headers()
    r = requests.get(
        f"{WAZUH_HOST}{path}",
        headers=headers,
        params=params or {},
        verify=False,
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def _parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─────────────────────────────────────────────────────
# Authentication Routes
# ─────────────────────────────────────────────────────
@app.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/api/v1/auth/login", methods=["POST"])
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

            if not row or not _verify_password(password, row["password_hash"]):
                return jsonify({"status": "error", "error": "invalid username or password"}), 401
            if row["status"] != "active":
                return jsonify({"status": "error", "error": "account is disabled"}), 403

            cur.execute("UPDATE users SET last_login = now() WHERE id = %s", (row["id"],))
            _audit(cur, "Login", row["username"], "Successful sign-in", actor=row["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    session.clear()
    session.permanent = True
    session["user_id"]     = row["id"]
    session["role"]        = row["role"]
    session["username"]    = row["username"]
    session["display_name"]= row["display_name"]

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


@app.route("/logout")
def logout_page():
    username = session.get("username")
    session.clear()
    if username:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                _audit(cur, "Logout", username, "Signed out", actor=username)
        except Exception:
            pass
    return redirect(url_for("login_page"))


@app.route("/api/v1/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
    return jsonify({"status": "success"})


@app.route("/api/v1/me/reset-password", methods=["POST"])
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
            cur.execute(
                "SELECT password_hash FROM users WHERE id = %s",
                (session["user_id"],),
            )
            row = cur.fetchone()
            if not row or not _verify_password(current, row["password_hash"]):
                return jsonify({"status": "error", "error": "current password is incorrect"}), 401

            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (_hash_password(new), session["user_id"]),
            )
            _audit(cur, "Password reset", session["username"],
                   "User reset their own password", actor=session["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success"})


# ─────────────────────────────────────────────────────
# UI pages (Protected)
# ─────────────────────────────────────────────────────
@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/health")
@login_required
def health_page():
    return render_template("health.html")


@app.route("/systems")
@login_required
def systems_page():
    return render_template("systems.html")


@app.route("/incidents")
@login_required
def incidents_page():
    return render_template("incidents.html")


@app.route("/incidents/<int:case_id>")
@login_required
def incident_detail_page(case_id):
    return render_template("case_detail.html", case_id=case_id)


# ─────────────────────────────────────────────────────
# Alerts feed API (Postgres-backed)
# ─────────────────────────────────────────────────────
LEVEL_TO_SEV = [
    (16, "critical"),
    (14, "high"),
    (12, "medium"),
    (0,  "low"),
]


def level_to_sev(level):
    lvl = level or 0
    for min_level, sev in LEVEL_TO_SEV:
        if lvl >= min_level:
            return sev
    return "low"


def classify_category(row):
    """
    Map a Wazuh alert row to one of bf / pe / fim / ra.

    Priority order:
      1. Explicit threat_type string (if Wazuh already labelled it)
      2. Known rule_id from your local ruleset
      3. MITRE technique family
      4. Fallback -> "bf" (most college-instance alerts are auth)

    Keep RULE_MAP in sync as you discover new rule IDs in the feed.
    """
    tt    = (row.get("threat_type") or "").lower()
    mitre = (row.get("mitre_id")    or "").upper()
    rule  = str(row.get("rule_id")  or "")

    # ── 1. Explicit threat_type ──
    if "ransom" in tt:
        return "ra"
    if "brute" in tt or "credential" in tt or "password" in tt:
        return "bf"
    if "privilege" in tt or "escalat" in tt:
        return "pe"
    if "integrity" in tt or "file" in tt or "fim" in tt:
        return "fim"

    # ── 2. Known rule IDs ──
    RULE_MAP = {
        # brute force / auth
        "110002": "bf",
        "40112":  "bf",
        "5763":   "bf",
        "5764":   "bf",
        "5765":   "bf",
        # privilege escalation
        "5403":   "pe",
        "5406":   "pe",
        # file integrity / tampering / log clearing / dropped files
        "5501":   "fim",
        "5502":   "fim",
        "5503":   "fim",
        "92213":  "fim",   # executable dropped in malware folder
        "100004": "fim",   # Windows Security Event Log cleared
        # ransomware
        "5800":   "ra",
        "5801":   "ra",
        "5802":   "ra",
    }
    if rule in RULE_MAP:
        return RULE_MAP[rule]

    # ── 3. MITRE technique family ──
    if mitre.startswith(("T1110", "T1078")):
        return "bf"
    if mitre.startswith(("T1068", "T1548", "T1055",
                         "T1134", "T1547", "T1626")):
        return "pe"
    if mitre.startswith(("T1486", "T1490")):
        return "ra"
    if mitre.startswith(("T1105", "T1565", "T1562",
                         "T1070", "T1543", "T1003")):
        return "fim"

    # ── 4. Fallback ──
    return "bf"


def row_to_alert(row):
    sev = level_to_sev(row["level"])
    category = classify_category(row)

    desc = row["description"] or "Detection"
    name = desc.split(".")[0]
    if len(name) > 70:
        name = name[:67] + "…"

    return {
        "id":          row["id"],
        "name":        name,
        "sev":         sev,
        "category":    category,
        "desc":        desc,
        "computer":    row["agent"] or "unknown",
        "ruleId":      row["rule_id"] or "—",
        "time":        row["time"].strftime("%d %b %Y, %H:%M IST") if row["time"] else "—",
        "source_ip":   row["source_ip"],
        "target_user": row["target_user"],
        "mitre_id":    row["mitre_id"],
    }


@app.route("/api/v1/alerts/feed")
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

    # ── Time range ──
    if from_s:
        try:
            where.append("time >= %s")
            params.append(datetime.fromisoformat(from_s.replace("Z", "+00:00")))
        except ValueError:
            return jsonify({"status": "error",
                            "error": f"invalid 'from' timestamp: {from_s}"}), 400

    if to_s:
        try:
            where.append("time <= %s")
            params.append(datetime.fromisoformat(to_s.replace("Z", "+00:00")))
        except ValueError:
            return jsonify({"status": "error",
                            "error": f"invalid 'to' timestamp: {to_s}"}), 400

    # ── Severity ──
    if sev in ("critical", "high", "medium", "low"):
        ranges = {"critical": (16, 999), "high": (14, 15),
                  "medium": (12, 13),      "low": (0, 11)}
        lo, hi = ranges[sev]
        where.append("level BETWEEN %s AND %s")
        params.extend([lo, hi])

    # ── Search ──
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


# ─────────────────────────────────────────────────────
# Dashboard aggregate API
# ─────────────────────────────────────────────────────
@app.route("/api/v1/dashboard")
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


# ─────────────────────────────────────────────────────
# Wazuh passthrough endpoints
# ─────────────────────────────────────────────────────
@app.route("/api/agents")
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


@app.route("/api/alerts")
@login_required
def api_alerts():
    try:
        payload = _wazuh_get("/alerts", {"limit": 10, "sort": "-timestamp"})
        return jsonify(payload.get("data", {}).get("affected_items", []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────
# Monitored Systems (Wazuh-backed)
# ─────────────────────────────────────────────────────
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


@app.route("/api/v1/systems")
@login_required
def api_systems():
    try:
        agents_payload = _wazuh_get("/agents", {"limit": 500})
    except Exception as e:
        return jsonify({"status": "error", "error": f"Wazuh agents: {e}"}), 502

    agents = agents_payload.get("data", {}).get("affected_items", [])

    alerts_by_agent = {}
    try:
        alerts_payload = _wazuh_get("/alerts", {"limit": 500, "sort": "-timestamp"})
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


# ─────────────────────────────────────────────────────
# Health checks
# ─────────────────────────────────────────────────────
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
                SELECT count(*) AS n,
                       min(time) AS oldest,
                       max(time) AS newest
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
                "last_seen": newest.isoformat(),
                "stale_sec": int(age),
                "rows": n}

    mins = int(age // 60)
    return {"name": "Alert sync", "status": "degraded",
            "detail": f"stale — last write {mins}m ago (threshold {POLLER_STALE_SEC}s)",
            "last_seen": newest.isoformat(),
            "stale_sec": int(age),
            "rows": n}


@app.route("/healthz")
def healthz():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 503


@app.route("/api/v1/health")
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


# ─────────────────────────────────────────────────────
# Incident Cases (raw psycopg2)
# ─────────────────────────────────────────────────────
THREAT_TO_PLAYBOOK = {
    "Brute Force":         "bruteforce",
    "Privilege Escalation": "privilege",
    "File Integrity":      "fileintegrity",
    "Ransomware":          "ransomware",
}
PLAYBOOK_TOTAL_STEPS = {
    "bruteforce":    7,
    "privilege":     7,
    "fileintegrity": 7,
    "ransomware":    7,
}
CASE_STATUSES = {
    "open", "investigating", "containing",
    "contained", "resolved", "false-positive",
}


def _row_to_case(row):
    """Turn a cases row (RealDictCursor) into the JSON shape the frontend wants."""
    opened = row["opened_at"]
    return {
        "id":               row["id"],
        "caseRef":          row["case_ref"],
        "status":           row["status"],
        "severity":         row["severity"],
        "threatType":       row["threat_type"],
        "playbookKey":      row["playbook_key"],
        "agent":            row["agent_name"],
        "agentIp":          row["agent_ip"],
        "sourceIp":         row["source_ip"],
        "targetUser":       row["target_user"],
        "title":            row["title"],
        "description":      row["description"],
        "assignedTo":       row["assigned_to"],
        "dataCategories":   row["data_categories"],
        "personsAffected":  row["persons_affected"] or 0,
        "curStep":          row["cur_step"],
        "totalSteps":       row["total_steps"],
        "openedAt":         opened.isoformat() if opened else None,
        "openedAtIst":      opened.astimezone(
                                timezone(timedelta(hours=5, minutes=30))
                            ).strftime("%d %b %Y, %H:%M IST") if opened else None,
        "updatedAt":        row["updated_at"].isoformat() if row["updated_at"] else None,
        "closedAt":         row["closed_at"].isoformat() if row["closed_at"] else None,
    }


def _next_case_ref(cur):
    """IR-01, IR-02, ... — zero-padded, based on MAX(id)."""
    cur.execute("SELECT coalesce(max(id), 0) + 1 AS n FROM cases")
    n = cur.fetchone()["n"]
    return f"IR-{n:02d}"


def _audit(cur, action, ref=None, detail=None, actor="System"):
    cur.execute(
        "INSERT INTO audit_log (action, ref, detail, actor) "
        "VALUES (%s, %s, %s, %s)",
        (action, ref, detail, actor),
    )


def _case_event(cur, case_id, kind, message, actor="System"):
    cur.execute(
        "INSERT INTO case_events (case_id, kind, message, actor) "
        "VALUES (%s, %s, %s, %s)",
        (case_id, kind, message, actor),
    )


@app.route("/api/v1/incidents", methods=["GET"])
@login_required
def api_incidents_list():
    """List cases. Supports ?tab=all|active|resolved, ?q=, ?assignee=, ?type="""
    tab      = (request.args.get("tab")      or "all").lower()
    q        = (request.args.get("q")        or "").strip()
    assignee = (request.args.get("assignee") or "").strip()
    threat   = (request.args.get("type")     or "").strip()

    where, params = [], []
    if tab == "active":
        where.append("status NOT IN ('resolved','false-positive')")
    elif tab == "resolved":
        where.append("status IN ('resolved','false-positive')")

    if q:
        like = f"%{q}%"
        where.append(
            "(case_ref ILIKE %s OR title ILIKE %s OR description ILIKE %s "
            "OR agent_name ILIKE %s OR assigned_to ILIKE %s)"
        )
        params.extend([like, like, like, like, like])
    if assignee:
        where.append("assigned_to = %s")
        params.append(assignee)
    if threat:
        where.append("threat_type = %s")
        params.append(threat)

    sql = """
        SELECT * FROM cases
        {where}
        ORDER BY
            CASE status
                WHEN 'open'           THEN 0
                WHEN 'investigating'  THEN 1
                WHEN 'containing'     THEN 2
                WHEN 'contained'      THEN 3
                WHEN 'resolved'       THEN 4
                WHEN 'false-positive' THEN 5
            END,
            opened_at DESC
    """.format(where=("WHERE " + " AND ".join(where)) if where else "")

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({
        "status": "success",
        "count":  len(rows),
        "data":   [_row_to_case(r) for r in rows],
    })


@app.route("/api/v1/incidents/<int:case_id>", methods=["GET"])
@login_required
def api_incident_get(case_id):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "error", "error": "case not found"}), 404

            cur.execute(
                "SELECT kind, message, actor, created_at "
                "FROM case_events WHERE case_id = %s ORDER BY created_at",
                (case_id,),
            )
            events = [{
                "kind":      r["kind"],
                "message":   r["message"],
                "actor":     r["actor"],
                "createdAt": r["created_at"].isoformat(),
                "createdAtIst": r["created_at"].astimezone(
                    timezone(timedelta(hours=5, minutes=30))
                ).strftime("%d %b %Y, %H:%M IST"),
            } for r in cur.fetchall()]

            cur.execute(
                "SELECT id, filename, kind, notes, uploaded_by, created_at "
                "FROM case_evidence WHERE case_id = %s ORDER BY created_at DESC",
                (case_id,),
            )
            evidence = [{
                "id":         r["id"],
                "filename":   r["filename"],
                "kind":       r["kind"],
                "notes":      r["notes"],
                "uploadedBy": r["uploaded_by"],
                "createdAt":  r["created_at"].isoformat(),
            } for r in cur.fetchall()]
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    case = _row_to_case(row)
    case["events"]   = events
    case["evidence"] = evidence

    pb = PLAYBOOKS.get(row["playbook_key"] or "")
    if pb:
        case["playbook"] = {
            "key":   row["playbook_key"],
            "name":  pb["name"],
            "steps": pb["steps"],
        }
    else:
        case["playbook"] = None

    return jsonify({"status": "success", "data": case})


@app.route("/api/v1/incidents", methods=["POST"])
@login_required
def api_incident_create():
    """Create a case manually (used by 'Report New Incident' modal)."""
    body = request.get_json(silent=True) or {}

    threat_type = (body.get("threatType") or "").strip()
    if threat_type not in THREAT_TO_PLAYBOOK:
        return jsonify({"status": "error",
                        "error": f"threatType must be one of {list(THREAT_TO_PLAYBOOK)}"}), 400

    agent       = (body.get("agent")       or "").strip() or "unknown"
    title       = (body.get("title")       or "").strip()
    description = (body.get("description") or "").strip()
    severity    = (body.get("severity")    or "medium").lower()
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"
    assigned_to = (body.get("assignedTo")  or "IT Team").strip()
    source_ip   = (body.get("sourceIp")    or "").strip() or None
    target_user = (body.get("targetUser")  or "").strip() or None
    data_cats   = (body.get("dataCategories") or "To be determined").strip()
    persons     = int(body.get("personsAffected") or 0)

    if not title:
        return jsonify({"status": "error", "error": "title is required"}), 400

    playbook_key = THREAT_TO_PLAYBOOK[threat_type]
    total_steps  = PLAYBOOK_TOTAL_STEPS[playbook_key]

    try:
        with get_conn() as conn, conn.cursor() as cur:
            case_ref = _next_case_ref(cur)

            cur.execute("""
                INSERT INTO cases (
                    case_ref, status, severity, threat_type, playbook_key,
                    agent_name, source_ip, target_user, title, description,
                    assigned_to, data_categories, persons_affected,
                    cur_step, total_steps
                ) VALUES (
                    %s, 'investigating', %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    0, %s
                )
                RETURNING id, case_ref, opened_at
            """, (
                case_ref, severity, threat_type, playbook_key,
                agent, source_ip, target_user, title, description,
                assigned_to, data_cats, persons,
                total_steps,
            ))
            new_row = cur.fetchone()

            _case_event(cur, new_row["id"], "opened",
                        f"Case {case_ref} opened — {threat_type} on {agent}",
                        actor="System")
            _audit(cur, "Case opened", case_ref,
                   f"{threat_type} on {agent}", actor="System")

            cur.execute("SELECT * FROM cases WHERE id = %s", (new_row["id"],))
            full = cur.fetchone()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": _row_to_case(full)}), 201


@app.route("/api/v1/incidents/<int:case_id>", methods=["PATCH"])
@login_required
def api_incident_update(case_id):
    """Update status / cur_step / assigned_to."""
    body = request.get_json(silent=True) or {}
    updates, params = [], []

    if "status" in body:
        status = (body["status"] or "").lower()
        if status not in CASE_STATUSES:
            return jsonify({"status": "error",
                            "error": f"status must be one of {sorted(CASE_STATUSES)}"}), 400
        updates.append("status = %s")
        params.append(status)

    if "curStep" in body:
        try:
            step = int(body["curStep"])
        except (TypeError, ValueError):
            return jsonify({"status": "error", "error": "curStep must be int"}), 400
        updates.append("cur_step = %s")
        params.append(step)

    if "assignedTo" in body:
        updates.append("assigned_to = %s")
        params.append(body["assignedTo"])

    if not updates:
        return jsonify({"status": "error", "error": "no valid fields to update"}), 400

    updates.append("updated_at = now()")
    params.append(case_id)

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                f"UPDATE cases SET {', '.join(updates)} WHERE id = %s RETURNING *",
                params,
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "error", "error": "case not found"}), 404

            if "status" in body:
                _case_event(cur, case_id, "status_change",
                            f"Status changed to {row['status']}", actor="System")
                _audit(cur, "Case status changed", row["case_ref"],
                       f"Status set to {row['status']}")
            if "curStep" in body:
                _case_event(cur, case_id, "step_change",
                            f"Step {row['cur_step']} of {row['total_steps']}")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": _row_to_case(row)})


@app.route("/api/v1/incidents/from-alert/<int:alert_id>", methods=["POST"])
@login_required
def api_incident_from_alert(alert_id):
    """One-click: turn a detection row into a case."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
            a = cur.fetchone()
            if not a:
                return jsonify({"status": "error", "error": "alert not found"}), 404

            cat = classify_category(a)
            threat_type = {
                "bf":  "Brute Force",
                "pe":  "Privilege Escalation",
                "fim": "File Integrity",
                "ra":  "Ransomware",
            }[cat]
            playbook_key = THREAT_TO_PLAYBOOK[threat_type]
            total_steps  = PLAYBOOK_TOTAL_STEPS[playbook_key]

            lvl = a["level"] or 0
            if   lvl > 15:   sev = "critical"
            elif lvl >= 14:  sev = "high"
            elif lvl >= 12:  sev = "medium"
            else:            sev = "low"

            case_ref = _next_case_ref(cur)
            title    = (a["description"] or "Detection")[:120]
            desc     = a["description"] or ""

            cur.execute("""
                INSERT INTO cases (
                    case_ref, status, severity, threat_type, playbook_key,
                    agent_name, agent_ip, source_ip, target_user,
                    title, description, assigned_to, data_categories,
                    persons_affected, cur_step, total_steps
                ) VALUES (
                    %s, 'investigating', %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, 'IT Team', 'To be assessed',
                    0, 0, %s
                )
                RETURNING id, case_ref
            """, (
                case_ref, sev, threat_type, playbook_key,
                a["agent"], a["agent_ip"], a["source_ip"], a["target_user"],
                title, desc, total_steps,
            ))
            new_row = cur.fetchone()

            _case_event(cur, new_row["id"], "opened",
                        f"Case {case_ref} opened from detection {alert_id}", actor="System")
            _audit(cur, "Case opened from detection", case_ref,
                   f"Alert #{alert_id} — {title}")

            cur.execute("SELECT * FROM cases WHERE id = %s", (new_row["id"],))
            full = cur.fetchone()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": _row_to_case(full)}), 201


# ─────────────────────────────────────────────────────
# Playbook step definitions
# ─────────────────────────────────────────────────────
PLAYBOOKS = {
    "ransomware": {
        "name": "Ransomware Analysis & Response Guide",
        "steps": [
            {"title": "Isolate the affected system",
             "plain": "Disconnect the affected computer from the network to stop active encryption and limit spread.",
             "linux": "sudo iptables -I INPUT -j DROP\nsudo iptables -I OUTPUT -j DROP",
             "windows": "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
             "expected": "The affected system can no longer communicate with the network."},
            {"title": "Identify the ransomware activity",
             "plain": "Identify the suspicious process, executable, file extensions, and network connections associated with the ransomware.",
             "linux": "ps aux --sort=-%cpu | head -20\nnetstat -tulnp",
             "windows": "Get-Process | Sort-Object CPU -Descending | Select -First 20\nnetstat -ano",
             "expected": "You have identified the suspicious process and relevant network indicators."},
            {"title": "Preserve evidence",
             "plain": "Capture logs, process information, network information, screenshots, and suspicious file details before removing the malware.",
             "linux": "dmesg > /tmp/kernel_log.txt\ncp /var/log/syslog /tmp/syslog_backup.txt",
             "windows": "Get-EventLog -LogName Security -Newest 500 | Export-Csv events.csv\nipconfig /all > network_info.txt",
             "expected": "Evidence is stored and can be attached to the incident case."},
            {"title": "Stop the malicious process",
             "plain": "Terminate the confirmed ransomware process after evidence has been preserved.",
             "linux": "sudo kill -9 [PID]",
             "windows": "Stop-Process -Id [PID] -Force",
             "expected": "The ransomware process is no longer running."},
            {"title": "Block the attacker connection",
             "plain": "Block identified command-and-control or malicious external addresses.",
             "linux": "sudo iptables -I OUTPUT -d [ATTACKER_IP] -j DROP",
             "windows": 'New-NetFirewallRule -DisplayName "Block Ransomware C2" -Direction Outbound -RemoteAddress [ATTACKER_IP] -Action Block',
             "expected": "The identified malicious connection is blocked."},
            {"title": "Recover and verify",
             "plain": "Restore affected files or systems from a known-clean backup.",
             "linux": "rsync -av /backup/pre-attack/ /data/restored/",
             "windows": "wbadmin start recovery -version:[BACKUP_VERSION]",
             "expected": "Clean data is restored and the recovered system passes basic verification."},
            {"title": "Confirm clean state and close",
             "plain": "Confirm the ransomware activity has stopped and the response record is complete before closing the incident.",
             "linux": "# Verify services, logs, and restored files before reconnecting the host",
             "windows": "# Verify services, logs, and restored files before reconnecting the host",
             "expected": "The environment is stable and the incident is ready to close."},
        ],
    },
    "bruteforce": {
        "name": "Brute Force Response Guide",
        "steps": [
            {"title": "Block the attacking source",
             "plain": "Block the source address responsible for the repeated authentication attempts.",
             "linux": "sudo iptables -I INPUT -s [ATTACKER_IP] -j DROP",
             "windows": 'New-NetFirewallRule -DisplayName "Block Brute Force" -Direction Inbound -RemoteAddress [ATTACKER_IP] -Action Block',
             "expected": "Further authentication attempts from the identified source are blocked."},
            {"title": "Protect targeted accounts",
             "plain": "Lock accounts receiving excessive failed login attempts.",
             "linux": "sudo passwd -l [username]",
             "windows": "Disable-ADAccount -Identity [username]",
             "expected": "Targeted accounts are protected from further access."},
            {"title": "Review authentication logs",
             "plain": "Determine which accounts were targeted and whether any successful login occurred.",
             "linux": "grep 'Failed password' /var/log/auth.log | tail -100\ngrep 'Accepted' /var/log/auth.log | tail -50",
             "windows": 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624,4625} -MaxEvents 100',
             "expected": "You know which accounts were targeted and whether successful authentication occurred."},
            {"title": "Reset affected credentials",
             "plain": "Reset credentials for accounts that were targeted or successfully accessed.",
             "linux": "sudo passwd [username]",
             "windows": "Set-ADAccountPassword -Identity [username] -Reset",
             "expected": "Affected accounts have new credentials."},
            {"title": "Strengthen authentication controls",
             "plain": "Review lockout and authentication controls to reduce the chance of repeated attacks.",
             "linux": "sudo systemctl enable fail2ban --now",
             "windows": "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00",
             "expected": "The environment has stronger controls against repeated authentication attempts."},
            {"title": "Document and close",
             "plain": "Record the attack source, affected accounts, successful logins, actions taken, and final outcome.",
             "linux": "# Complete incident notes and close when verified",
             "windows": "# Complete incident notes and close when verified",
             "expected": "The incident has a complete response record."},
            {"title": "Verify and close the case",
             "plain": "Confirm repeated authentication attempts have stopped and the response record is complete.",
             "linux": "# Review recent authentication events",
             "windows": "# Review recent Security events",
             "expected": "No continued brute force activity is observed and the case is ready to close."},
        ],
    },
    "privilege": {
        "name": "Privilege Escalation Response Guide",
        "steps": [
            {"title": "Identify the account and command",
             "plain": "Confirm which account performed the unexpected administrative action.",
             "linux": "last -F [username]\nhistory | tail -50",
             "windows": 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688} -MaxEvents 100',
             "expected": "The account, command, time, and system are identified."},
            {"title": "Preserve relevant evidence",
             "plain": "Save authentication, process, and system logs before changing the account.",
             "linux": "cp /var/log/auth.log /tmp/auth_evidence.log\nps aux > /tmp/processes.txt",
             "windows": "Get-WinEvent -LogName Security -MaxEvents 500 | Export-Csv security_events.csv",
             "expected": "Relevant evidence is preserved."},
            {"title": "Restrict suspicious access",
             "plain": "Temporarily remove elevated access or lock the account if the activity is not authorised.",
             "linux": "sudo passwd -l [username]",
             "windows": "Disable-ADAccount -Identity [username]",
             "expected": "The suspicious account can no longer perform additional privileged actions."},
            {"title": "Check for persistence",
             "plain": "Look for newly created admin accounts, scheduled tasks, services, startup entries.",
             "linux": "getent group sudo\nsystemctl list-unit-files --state=enabled",
             "windows": "Get-LocalGroupMember Administrators\nGet-ScheduledTask",
             "expected": "No unauthorised persistence remains, or suspicious persistence is documented."},
            {"title": "Restore approved privileges",
             "plain": "Remove unauthorised privilege changes and restore the account to its approved role.",
             "linux": "# Remove unauthorised group membership and restore approved access",
             "windows": "# Remove unauthorised group membership and restore approved access",
             "expected": "The account has only its approved permissions."},
            {"title": "Document and close",
             "plain": "Record the escalation path, evidence, containment actions, and final determination.",
             "linux": "# Complete incident notes and close when verified",
             "windows": "# Complete incident notes and close when verified",
             "expected": "The privilege escalation incident is fully documented."},
            {"title": "Verify and close the case",
             "plain": "Confirm approved access is restored and the incident record is complete.",
             "linux": "# Verify approved privileges",
             "windows": "# Verify approved privileges",
             "expected": "Approved access is confirmed and the case is ready to close."},
        ],
    },
    "fileintegrity": {
        "name": "File Integrity Management Response Guide",
        "steps": [
            {"title": "Identify the changed files",
             "plain": "Review the file integrity alert and identify which protected files changed.",
             "linux": "stat [FILE]\nls -l [FILE]",
             "windows": "Get-Item [FILE] | Format-List *",
             "expected": "The changed files and timestamps are identified."},
            {"title": "Preserve evidence",
             "plain": "Capture the current file state, relevant logs, and the account responsible.",
             "linux": "sha256sum [FILE] > /tmp/file_hash.txt\ncp /var/log/auth.log /tmp/auth_evidence.log",
             "windows": "Get-FileHash [FILE] -Algorithm SHA256 | Out-File file_hash.txt",
             "expected": "The original change and supporting evidence are recorded."},
            {"title": "Determine whether the change was authorised",
             "plain": "Compare the change with approved maintenance, deployment, or admin activity.",
             "linux": "# Compare timestamps with approved maintenance records",
             "windows": "# Compare timestamps with approved maintenance records",
             "expected": "The change is classified as authorised or suspicious."},
            {"title": "Contain suspicious activity",
             "plain": "If the change is unauthorised, restrict the responsible account or process.",
             "linux": "sudo passwd -l [username]",
             "windows": "Disable-ADAccount -Identity [username]",
             "expected": "Further unauthorised changes are prevented while investigation continues."},
            {"title": "Restore the approved file state",
             "plain": "Restore the affected configuration from a known-good source.",
             "linux": "cp /backup/approved/[FILE] [FILE]",
             "windows": "# Restore the approved file version from your configuration backup",
             "expected": "The protected file matches the approved configuration."},
            {"title": "Document and close",
             "plain": "Record the changed files, authorisation decision, evidence, corrective action, and final outcome.",
             "linux": "# Complete incident notes and close when verified",
             "windows": "# Complete incident notes and close when verified",
             "expected": "The file integrity incident is fully documented."},
            {"title": "Verify system stability and close",
             "plain": "Monitor the protected files after restoration to confirm no unexpected changes recur.",
             "linux": "# Verify file hashes and monitor for additional changes",
             "windows": "# Verify file hashes and monitor for additional changes",
             "expected": "The approved file state remains stable and the case is ready to close."},
        ],
    },
}


@app.route("/api/v1/playbooks/<key>", methods=["GET"])
@login_required
def api_playbook_get(key):
    """Return the playbook step definitions for a given key."""
    pb = PLAYBOOKS.get(key)
    if not pb:
        return jsonify({"status": "error", "error": f"unknown playbook '{key}'"}), 404
    return jsonify({
        "status":   "success",
        "key":      key,
        "name":     pb["name"],
        "steps":    pb["steps"],
        "totalSteps": len(pb["steps"]),
    })


@app.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/complete", methods=["POST"])
@login_required
def api_step_complete(case_id, step_num):
    """Mark step N done. Bumps cur_step, logs a case event."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cur.fetchone()
            if not case:
                return jsonify({"status": "error", "error": "case not found"}), 404

            if step_num != case["cur_step"]:
                return jsonify({"status": "error",
                                "error": f"step out of order (cur={case['cur_step']}, got={step_num})"}), 400
            if case["cur_step"] >= case["total_steps"]:
                return jsonify({"status": "error", "error": "all steps already complete"}), 400

            new_step = case["cur_step"] + 1
            new_status = case["status"]
            if new_step >= case["total_steps"]:
                new_status = "contained"

            cur.execute(
                "UPDATE cases SET cur_step = %s, status = %s, updated_at = now() "
                "WHERE id = %s RETURNING *",
                (new_step, new_status, case_id),
            )
            updated = cur.fetchone()

            pb = PLAYBOOKS.get(case["playbook_key"] or "", {"steps": []})
            step_title = pb["steps"][step_num]["title"] if step_num < len(pb["steps"]) else f"Step {step_num+1}"
            _case_event(cur, case_id, "step_done",
                        f"Step {step_num + 1} completed — {step_title}")
            _audit(cur, "Playbook step completed", case["case_ref"],
                   f"Step {step_num + 1}: {step_title}")
            if new_step >= case["total_steps"]:
                _case_event(cur, case_id, "status_change",
                            "All steps complete — case moved to Contained")
                _audit(cur, "Playbook completed", case["case_ref"],
                       "All response steps completed")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": _row_to_case(updated)})


@app.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/undo", methods=["POST"])
@login_required
def api_step_undo(case_id, step_num):
    """Undo step N (only if it was the last completed one)."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cur.fetchone()
            if not case:
                return jsonify({"status": "error", "error": "case not found"}), 404
            if case["cur_step"] == 0:
                return jsonify({"status": "error", "error": "no steps to undo"}), 400
            if step_num != case["cur_step"] - 1:
                return jsonify({"status": "error",
                                "error": f"can only undo the last completed step (cur={case['cur_step']})"}), 400

            new_step = case["cur_step"] - 1
            cur.execute(
                "UPDATE cases SET cur_step = %s, updated_at = now() "
                "WHERE id = %s RETURNING *",
                (new_step, case_id),
            )
            updated = cur.fetchone()

            pb = PLAYBOOKS.get(case["playbook_key"] or "", {"steps": []})
            step_title = pb["steps"][step_num]["title"] if step_num < len(pb["steps"]) else f"Step {step_num+1}"
            _case_event(cur, case_id, "step_undo",
                        f"Step {step_num + 1} undone — {step_title}")
            _audit(cur, "Playbook step undone", case["case_ref"],
                   f"Step {step_num + 1}")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": _row_to_case(updated)})


@app.route("/api/v1/incidents/<int:case_id>/evidence", methods=["POST"])
@login_required
def api_case_evidence_add(case_id):
    """Attach an evidence entry. Frontend uploads only the filename (no file bytes)."""
    body = request.get_json(silent=True) or {}
    filename = (body.get("filename") or "").strip()
    if not filename:
        return jsonify({"status": "error", "error": "filename is required"}), 400
    kind   = (body.get("kind")  or "Other").strip()
    notes  = (body.get("notes") or "").strip() or None
    actor  = (body.get("uploadedBy") or "IT Team").strip()

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT case_ref FROM cases WHERE id = %s", (case_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "error", "error": "case not found"}), 404

            cur.execute(
                "INSERT INTO case_evidence (case_id, filename, kind, notes, uploaded_by) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING *",
                (case_id, filename, kind, notes, actor),
            )
            ev = cur.fetchone()

            _case_event(cur, case_id, "evidence",
                        f"Evidence attached — {filename}", actor=actor)
            _audit(cur, "Evidence attached", row["case_ref"], filename, actor=actor)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": {
        "id":         ev["id"],
        "filename":   ev["filename"],
        "kind":       ev["kind"],
        "notes":      ev["notes"],
        "uploadedBy": ev["uploaded_by"],
        "createdAt":  ev["created_at"].isoformat(),
    }}), 201


# ─────────────────────────────────────────────────────
# Playbooks library
# ─────────────────────────────────────────────────────
@app.route("/playbooks")
@login_required
def playbooks_page():
    return render_template("playbooks.html")


@app.route("/api/v1/playbooks", methods=["GET"])
@login_required
def api_playbooks_list():
    """List all playbooks with active-case counts."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT playbook_key,count(*) FILTER (WHERE status NOT IN ('resolved','false-positive')) AS active_count,count(*) AS total_count
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
            "key":            key,
            "name":           pb["name"],
            "description":    _playbook_description(key),
            "stepCount":      len(pb["steps"]),
            "activeCases":    c["active"],
            "totalCases":     c["total"],
            "currentCase":    active_cases.get(key),
        })

    return jsonify({"status": "success", "count": len(out), "data": out})


def _playbook_description(key):
    return {
        "ransomware":    "Analyse ransomware activity, preserve evidence, contain the attack, block malicious connections, and recover safely.",
        "bruteforce":    "Block repeated authentication attempts, protect targeted accounts, review authentication logs, and strengthen controls.",
        "privilege":     "Investigate unexpected administrative activity, preserve evidence, restrict suspicious access, and restore approved privileges.",
        "fileintegrity": "Identify protected-file changes, determine whether they were authorised, restore approved state, and document the outcome.",
    }.get(key, "Structured response procedure.")


# ─────────────────────────────────────────────────────
# Incident Reports
# ─────────────────────────────────────────────────────
@app.route("/report")
@login_required
def report_page():
    return render_template("report.html")


def _report_snapshot(case_row, events, evidence):
    """Build the immutable JSON payload that gets stored in reports.snapshot."""
    c = _row_to_case(case_row)
    return {
        "case":      c,
        "events":    events,
        "evidence":  evidence,
        "generated": datetime.now(timezone.utc).isoformat(),
    }


def _build_report_payload(case_id, cur):
    """Shared logic: fetch case + events + evidence, and return a preview dict."""
    cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
    row = cur.fetchone()
    if not row:
        return None, "case not found"

    pb = PLAYBOOKS.get(row["playbook_key"] or "")
    if not pb:
        return None, "no playbook for case"
    if row["cur_step"] < row["total_steps"]:
        return None, f"playbook incomplete ({row['cur_step']}/{row['total_steps']} steps done)"

    cur.execute(
        "SELECT kind, message, actor, created_at "
        "FROM case_events WHERE case_id = %s ORDER BY created_at",
        (case_id,),
    )
    events = [{
        "kind":         r["kind"],
        "message":      r["message"],
        "actor":        r["actor"],
        "createdAt":    r["created_at"].isoformat(),
        "createdAtIst": r["created_at"].astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ).strftime("%d %b %Y, %H:%M IST"),
    } for r in cur.fetchall()]

    cur.execute(
        "SELECT id, filename, kind, notes, uploaded_by, created_at "
        "FROM case_evidence WHERE case_id = %s ORDER BY created_at",
        (case_id,),
    )
    evidence = [{
        "id":         r["id"],
        "filename":   r["filename"],
        "kind":       r["kind"],
        "notes":      r["notes"],
        "uploadedBy": r["uploaded_by"],
        "createdAt":  r["created_at"].isoformat(),
    } for r in cur.fetchall()]

    case  = _row_to_case(row)
    pbdef = {"key": row["playbook_key"], "name": pb["name"], "steps": pb["steps"]}

    settings = _get_settings(cur)

    cert_email = _compose_cert_email(case, events, settings)

    return {
        "case":         case,
        "playbook":     pbdef,
        "events":       events,
        "evidence":     evidence,
        "organisation": {
            "name":  settings["orgName"],
            "type":  settings["orgType"],
            "city":  settings["city"],
            "state": settings["state"],
            "dpoName":  settings["dpoName"],
            "dpoEmail": settings["dpoEmail"],
        },
        "certEmail":    cert_email,
        "generatedAt":  datetime.now(timezone.utc).isoformat(),
    }, None


def _compose_cert_email(case, events, settings):
    """Plain-text CERT-In data-breach notification, DPDP Act 2023 §8(6)."""
    when    = case.get("openedAtIst") or "—"
    caseRef = case.get("caseRef")     or "—"
    agent   = case.get("agent")       or "—"
    threat  = case.get("threatType")  or "—"
    persons = case.get("personsAffected") or 0
    cats    = case.get("dataCategories") or "To be determined"

    org_name  = settings.get("orgName")  or "Kumaraguru College of Technology"
    org_city  = settings.get("city")     or "Coimbatore"
    org_state = settings.get("state")    or "Tamil Nadu"
    dpo_name  = settings.get("dpoName")  or "Data Protection Officer"
    dpo_email = settings.get("dpoEmail") or ""

    steps = [e["message"] for e in events if e["kind"] == "step_done"]

    lines = [
        "To: incident@cert-in.org.in",
        f"Subject: Data Breach Notification — {org_name} — {caseRef}",
        "",
        "Dear CERT-In Team,",
        "",
        "We are reporting a data breach as required under the Digital Personal",
        "Data Protection Act 2023, Section 8(6).",
        "",
        f"Organisation: {org_name}, {org_city}, {org_state}",
        f"Case Reference: {caseRef}",
        f"Incident Type: {threat}",
        f"Affected System: {agent}",
        f"Data Categories Affected: {cats}",
        f"Approximate Persons Affected: {persons}",
        f"Date & Time of Discovery: {when}",
        "",
        "Response Actions Taken:",
    ]
    if steps:
        for i, s in enumerate(steps, 1):
            lines.append(f"  {i}. {s}")
    else:
        lines.append("  (see attached incident report)")

    lines.append("")
    lines.append("Immediate containment steps have been taken and the affected system")
    lines.append("has been secured. A full incident report is attached to this notification.")
    lines.append("")
    lines.append("Yours sincerely,")
    lines.append(dpo_name)
    if dpo_email:
        lines.append(dpo_email)
    lines.append(f"{org_name}, {org_city}")

    return "\n".join(lines)


@app.route("/api/v1/reports", methods=["GET"])
@login_required
def api_reports_list():
    """List previously generated reports."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT r.id, r.report_ref, r.case_id, r.created_at, r.generated_by,
                       c.case_ref, c.threat_type, c.severity
                FROM reports r
                JOIN cases c ON c.id = r.case_id
                ORDER BY r.created_at DESC
                LIMIT 50
            """)
            rows = cur.fetchall()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = [{
        "id":         r["id"],
        "reportRef":  r["report_ref"],
        "caseId":     r["case_id"],
        "caseRef":    r["case_ref"],
        "threatType": r["threat_type"],
        "severity":   r["severity"],
        "generatedBy":r["generated_by"],
        "generatedAt": r["created_at"].isoformat(),
        "generatedAtIst": r["created_at"].astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ).strftime("%d %b %Y, %H:%M IST"),
    } for r in rows]

    return jsonify({"status": "success", "count": len(data), "data": data})


@app.route("/api/v1/reports/preview/<int:case_id>", methods=["GET"])
@login_required
def api_report_preview(case_id):
    """Preview payload for the report builder — no DB write."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            payload, err = _build_report_payload(case_id, cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    if err:
        return jsonify({"status": "error", "error": err}), 400

    return jsonify({"status": "success", "data": payload})


@app.route("/api/v1/reports", methods=["POST"])
@login_required
def api_report_generate():
    """Generate and persist a report. Body: {caseId, generatedBy}."""
    body = request.get_json(silent=True) or {}
    try:
        case_id = int(body.get("caseId"))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "error": "caseId (int) is required"}), 400
    actor = (body.get("generatedBy") or "IT Team").strip()

    try:
        with get_conn() as conn, conn.cursor() as cur:
            payload, err = _build_report_payload(case_id, cur)
            if err:
                return jsonify({"status": "error", "error": err}), 400

            case_ref = payload["case"]["caseRef"]
            year     = datetime.now().year

            cur.execute(
                "SELECT count(*) AS n FROM reports WHERE case_id = %s", (case_id,)
            )
            seq = int(cur.fetchone()["n"]) + 1
            report_ref = f"ZR-{case_ref}-{year}-{seq:02d}"

            cur.execute(
                "INSERT INTO reports (report_ref, case_id, snapshot, generated_by) "
                "VALUES (%s, %s, %s, %s) RETURNING id, report_ref, created_at",
                (report_ref, case_id, psycopg2.extras.Json(payload), actor),
            )
            r = cur.fetchone()

            _case_event(cur, case_id, "report",
                        f"Report generated — {r['report_ref']}", actor=actor)
            _audit(cur, "Report generated", case_ref, r["report_ref"], actor=actor)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": {
        "id":         r["id"],
        "reportRef":  r["report_ref"],
        "createdAt":  r["created_at"].isoformat(),
        "caseId":     case_id,
        "caseRef":    payload["case"]["caseRef"],
        "payload":    payload,
    }}), 201


@app.route("/api/v1/reports/<int:report_id>", methods=["GET"])
@login_required
def api_report_get(report_id):
    """Fetch a stored report by id (full snapshot)."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, report_ref, case_id, snapshot, generated_by, created_at "
                "FROM reports WHERE id = %s", (report_id,),
            )
            r = cur.fetchone()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    if not r:
        return jsonify({"status": "error", "error": "report not found"}), 404

    return jsonify({"status": "success", "data": {
        "id":         r["id"],
        "reportRef":  r["report_ref"],
        "caseId":     r["case_id"],
        "generatedBy":r["generated_by"],
        "createdAt":  r["created_at"].isoformat(),
        "payload":    r["snapshot"],
    }})


# ─────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────
@app.route("/audit")
@login_required
def audit_page():
    return render_template("audit.html")


@app.route("/api/v1/audit", methods=["GET"])
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


# ─────────────────────────────────────────────────────
# Attack Analysis
# ─────────────────────────────────────────────────────
THREAT_LABELS = {
    "bf":  "Brute Force",
    "pe":  "Privilege Escalation",
    "fim": "File Integrity",
    "ra":  "Ransomware",
}


@app.route("/analysis")
@login_required
def analysis_page():
    return render_template("analysis.html")


@app.route("/api/v1/analysis", methods=["GET"])
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
        top_agents = sorted(
            cat_agents[key].items(), key=lambda kv: kv[1], reverse=True
        )[:3]
        cards.append({
            "key":       key,
            "label":     label,
            "count":     n,
            "pct":       pct,
            "topAgents": [{"agent": a, "count": c} for a, c in top_agents],
        })

    trend = [{"date": d.isoformat(), **trend_map[d]} for d in day_labels]

    targets = sorted(
        agent_breakdown.items(), key=lambda kv: sum(kv[1].values()), reverse=True
    )[:6]
    targets_out = [
        {"agent": a, "count": sum(b.values()), "breakdown": b}
        for a, b in targets
    ]

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


# ─────────────────────────────────────────────────────
# Statistics / Metrics
# ─────────────────────────────────────────────────────
@app.route("/metrics")
@login_required
def metrics_page():
    return render_template("metrics.html")


@app.route("/api/v1/metrics", methods=["GET"])
@login_required
def api_metrics():
    now = datetime.now(timezone.utc)
    start_of_window = (now - timedelta(days=6)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT
                    count(*) AS total,
                    count(*) FILTER (WHERE time > now() - interval '24 hours') AS last24h
                FROM alerts
            """)
            alert_stats = dict(cur.fetchone())

            cur.execute("""
                SELECT
                    count(*) AS total,
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
        trend_30.append({
            "date":        d.isoformat(),
            "mttdMinutes": mttd,
            "mttrMinutes": mttr,
        })

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


# ─────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────
SETTINGS_FIELDS = (
    "org_name", "org_type", "city", "state",
    "dpo_name", "dpo_email", "dpo_phone",
    "dpdp_id", "autoreport",
)


def _get_settings(cur):
    """Always returns a dict — row is guaranteed by the schema seed."""
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


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")


@app.route("/api/v1/settings", methods=["GET"])
@login_required
def api_settings_get():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            s = _get_settings(cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    return jsonify({"status": "success", "data": s})


@app.route("/api/v1/settings", methods=["PUT"])
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
            cur.execute(
                f"UPDATE settings SET {', '.join(updates)} WHERE id = 1",
                params,
            )
            _audit(cur, "Settings updated", "Settings",
                   ", ".join(mapping[k] for k in body if k in mapping),
                   actor="Administrator")
            s = _get_settings(cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": s})


# ─────────────────────────────────────────────────────
# Users (admin only)
# ─────────────────────────────────────────────────────
@app.route("/settings/users")
@login_required
def users_page():
    return render_template("users.html")


@app.route("/api/v1/users", methods=["GET"])
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


@app.route("/api/v1/users", methods=["POST"])
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
                (username, display, email, _hash_password(password), role),
            )
            new = cur.fetchone()
            _audit(cur, "User created", new["username"],
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


@app.route("/api/v1/users/<int:user_id>", methods=["PATCH"])
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
            cur.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING *",
                params,
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"status": "error", "error": "user not found"}), 404
            _audit(cur, "User updated", row["username"],
                   ", ".join(f"{k}={v}" for k, v in body.items()),
                   actor=session["display_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success"})


# ─────────────────────────────────────────────────────
# Dev entrypoint
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)