"""Incident report generation and persistence."""
from datetime import datetime, timezone, timedelta

import psycopg2.extras
from flask import Blueprint, jsonify, request

from ..db import get_conn
from ..helpers import login_required, audit, case_event, row_to_case
from ..playbooks import PLAYBOOKS


bp = Blueprint("reports", __name__)


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


def _compose_cert_email(case, events, settings):
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

    steps = [e["message"] for e in events if e["kind"] in ("step_done", "step_run")]
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


def _build_report_payload(case_id, cur):
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

    case     = row_to_case(row)
    pbdef    = {"key": row["playbook_key"], "name": pb["name"], "steps": pb["steps"]}
    settings = _get_settings(cur)
    cert_email = _compose_cert_email(case, events, settings)

    return {
        "case":         case,
        "playbook":     pbdef,
        "events":       events,
        "evidence":     evidence,
        "organisation": {
            "name":     settings["orgName"],
            "type":     settings["orgType"],
            "city":     settings["city"],
            "state":    settings["state"],
            "dpoName":  settings["dpoName"],
            "dpoEmail": settings["dpoEmail"],
        },
        "certEmail":    cert_email,
        "generatedAt":  datetime.now(timezone.utc).isoformat(),
    }, None


@bp.route("/api/v1/reports", methods=["GET"])
@login_required
def api_reports_list():
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


@bp.route("/api/v1/reports/preview/<int:case_id>", methods=["GET"])
@login_required
def api_report_preview(case_id):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            payload, err = _build_report_payload(case_id, cur)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    if err:
        return jsonify({"status": "error", "error": err}), 400
    return jsonify({"status": "success", "data": payload})


@bp.route("/api/v1/reports", methods=["POST"])
@login_required
def api_report_generate():
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

            cur.execute("SELECT count(*) AS n FROM reports WHERE case_id = %s", (case_id,))
            seq = int(cur.fetchone()["n"]) + 1
            report_ref = f"ZR-{case_ref}-{year}-{seq:02d}"

            cur.execute(
                "INSERT INTO reports (report_ref, case_id, snapshot, generated_by) "
                "VALUES (%s, %s, %s, %s) RETURNING id, report_ref, created_at",
                (report_ref, case_id, psycopg2.extras.Json(payload), actor),
            )
            r = cur.fetchone()

            case_event(cur, case_id, "report",
                       f"Report generated — {r['report_ref']}", actor=actor)
            audit(cur, "Report generated", case_ref, r["report_ref"], actor=actor)
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


@bp.route("/api/v1/reports/<int:report_id>", methods=["GET"])
@login_required
def api_report_get(report_id):
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