"""Shared decorators, audit helpers, and row serializers."""
from datetime import timezone, timedelta
from functools import wraps

from flask import session, redirect, url_for, request, abort

from .db import get_conn


IST = timezone(timedelta(hours=5, minutes=30))


# ── Auth decorators ───────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login_page", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login_page", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ── Audit / event helpers ─────────────────────────────
def audit(cur, action, ref=None, detail=None, actor="System"):
    cur.execute(
        "INSERT INTO audit_log (action, ref, detail, actor) VALUES (%s, %s, %s, %s)",
        (action, ref, detail, actor),
    )


def case_event(cur, case_id, kind, message, actor="System"):
    cur.execute(
        "INSERT INTO case_events (case_id, kind, message, actor) VALUES (%s, %s, %s, %s)",
        (case_id, kind, message, actor),
    )


def lookup_agent_os(cur, agent_name):
    """Return 'windows' | 'linux' for the agent, or None if unknown."""
    if not agent_name:
        return None
    cur.execute("SELECT os FROM agents WHERE name = %s", (agent_name,))
    r = cur.fetchone()
    return r["os"] if r else None


def row_to_case(row):
    opened = row["opened_at"]
    mode = row["mode"] if "mode" in row.keys() else "assisted"
    return {
        "id":               row["id"],
        "caseRef":          row["case_ref"],
        "status":           row["status"],
        "severity":         row["severity"],
        "threatType":       row["threat_type"],
        "playbookKey":      row["playbook_key"],
        "mode":             mode,
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
        "openedAtIst":      opened.astimezone(IST).strftime("%d %b %Y, %H:%M IST") if opened else None,
        "updatedAt":        row["updated_at"].isoformat() if row["updated_at"] else None,
        "closedAt":         row["closed_at"].isoformat() if row["closed_at"] else None,
    }


def next_case_ref(cur):
    cur.execute("SELECT coalesce(max(id), 0) + 1 AS n FROM cases")
    return f"IR-{cur.fetchone()['n']:02d}"


# ── Alert classification ──────────────────────────────
LEVEL_TO_SEV = [(16, "critical"), (14, "high"), (12, "medium"), (0, "low")]


def level_to_sev(level):
    lvl = level or 0
    for min_level, sev in LEVEL_TO_SEV:
        if lvl >= min_level:
            return sev
    return "low"


def classify_category(row):
    tt    = (row.get("threat_type") or "").lower()
    mitre = (row.get("mitre_id")    or "").upper()
    rule  = str(row.get("rule_id")  or "")

    if "ransom" in tt:                        return "ra"
    if "brute" in tt or "credential" in tt or "password" in tt: return "bf"
    if "privilege" in tt or "escalat" in tt:  return "pe"
    if "integrity" in tt or "file" in tt or "fim" in tt:        return "fim"

    RULE_MAP = {
        "110002": "bf", "40112": "bf", "5763": "bf", "5764": "bf", "5765": "bf",
        "5403": "pe",   "5406": "pe",
        "5501": "fim",  "5502": "fim", "5503": "fim", "92213": "fim", "100004": "fim",
        "5800": "ra",   "5801": "ra",  "5802": "ra",
    }
    if rule in RULE_MAP:
        return RULE_MAP[rule]

    if mitre.startswith(("T1110", "T1078")):                                        return "bf"
    if mitre.startswith(("T1068", "T1548", "T1055", "T1134", "T1547", "T1626")):   return "pe"
    if mitre.startswith(("T1486", "T1490")):                                        return "ra"
    if mitre.startswith(("T1105", "T1565", "T1562", "T1070", "T1543", "T1003")):   return "fim"

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