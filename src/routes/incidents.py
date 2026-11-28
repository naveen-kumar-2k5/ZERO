"""Incident cases CRUD, step execution, evidence."""
from datetime import timezone, timedelta

from flask import Blueprint, jsonify, request, session

from ..db import get_conn
from ..helpers import (
    login_required, audit, case_event, row_to_case, next_case_ref,
    lookup_agent_os, classify_category,
)
from ..playbooks import (
    PLAYBOOKS, THREAT_TO_PLAYBOOK, PLAYBOOK_TOTAL_STEPS, CASE_STATUSES,
    playbook_description,
)

# Kept at project root (alongside app.py)
from sender import send_command


bp = Blueprint("incidents", __name__)


# ── CRUD ──────────────────────────────────────────────
@bp.route("/api/v1/incidents", methods=["GET"])
@login_required
def api_incidents_list():
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

    data = [row_to_case(r) for r in rows]
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT name, os FROM agents")
            os_by_name = {r["name"]: r["os"] for r in cur.fetchall()}
        for c in data:
            c["agentOs"] = os_by_name.get(c["agent"])
    except Exception:
        for c in data:
            c["agentOs"] = None

    return jsonify({"status": "success", "count": len(data), "data": data})


@bp.route("/api/v1/incidents/<int:case_id>", methods=["GET"])
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

            agent_os = lookup_agent_os(cur, row["agent_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    case = row_to_case(row)
    case["events"]   = events
    case["evidence"] = evidence
    case["agentOs"]  = agent_os

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


@bp.route("/api/v1/incidents", methods=["POST"])
@login_required
def api_incident_create():
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
    mode        = (body.get("mode") or "assisted").lower()
    if mode not in ("manual", "assisted"):
        mode = "assisted"

    if not title:
        return jsonify({"status": "error", "error": "title is required"}), 400

    playbook_key = THREAT_TO_PLAYBOOK[threat_type]
    total_steps  = PLAYBOOK_TOTAL_STEPS[playbook_key]

    try:
        with get_conn() as conn, conn.cursor() as cur:
            case_ref = next_case_ref(cur)

            cur.execute("""
                INSERT INTO cases (
                    case_ref, status, severity, threat_type, playbook_key, mode,
                    agent_name, source_ip, target_user, title, description,
                    assigned_to, data_categories, persons_affected,
                    cur_step, total_steps
                ) VALUES (
                    %s, 'investigating', %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    0, %s
                )
                RETURNING id, case_ref, opened_at
            """, (
                case_ref, severity, threat_type, playbook_key, mode,
                agent, source_ip, target_user, title, description,
                assigned_to, data_cats, persons,
                total_steps,
            ))
            new_row = cur.fetchone()

            case_event(cur, new_row["id"], "opened",
                       f"Case {case_ref} opened — {threat_type} on {agent}",
                       actor="System")
            audit(cur, "Case opened", case_ref,
                  f"{threat_type} on {agent}", actor="System")

            cur.execute("SELECT * FROM cases WHERE id = %s", (new_row["id"],))
            full = cur.fetchone()
            agent_os = lookup_agent_os(cur, full["agent_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = row_to_case(full)
    data["agentOs"] = agent_os
    return jsonify({"status": "success", "data": data}), 201


@bp.route("/api/v1/incidents/<int:case_id>", methods=["PATCH"])
@login_required
def api_incident_update(case_id):
    body = request.get_json(silent=True) or {}
    updates, params = [], []

    if "status" in body:
        status = (body["status"] or "").lower()
        if status not in CASE_STATUSES:
            return jsonify({"status": "error",
                            "error": f"status must be one of {sorted(CASE_STATUSES)}"}), 400
        updates.append("status = %s")
        params.append(status)

    if "mode" in body:
        mode = (body["mode"] or "").lower()
        if mode not in ("manual", "assisted"):
            return jsonify({"status": "error",
                            "error": "mode must be 'manual' or 'assisted'"}), 400
        updates.append("mode = %s")
        params.append(mode)

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

    if "sourceIp" in body:
        updates.append("source_ip = %s")
        params.append((body["sourceIp"] or "").strip() or None)

    if "targetUser" in body:
        updates.append("target_user = %s")
        params.append((body["targetUser"] or "").strip() or None)

    if "agent" in body:
        updates.append("agent_name = %s")
        params.append((body["agent"] or "").strip() or None)

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
                case_event(cur, case_id, "status_change",
                           f"Status changed to {row['status']}", actor="System")
                audit(cur, "Case status changed", row["case_ref"],
                      f"Status set to {row['status']}")

            if "mode" in body:
                case_event(cur, case_id, "mode_change",
                           f"Mode changed to {row['mode']}", actor="System")
                audit(cur, "Case mode changed", row["case_ref"],
                      f"Mode set to {row['mode']}")

            if "curStep" in body:
                case_event(cur, case_id, "step_change",
                           f"Step {row['cur_step']} of {row['total_steps']}")

            if "assignedTo" in body:
                case_event(cur, case_id, "case_edit",
                           f"Assignee set to {row['assigned_to'] or '(unassigned)'}")

            if "sourceIp" in body:
                case_event(cur, case_id, "case_edit",
                           f"Source IP set to {row['source_ip'] or '(cleared)'}")

            if "targetUser" in body:
                case_event(cur, case_id, "case_edit",
                           f"Target user set to {row['target_user'] or '(cleared)'}")

            if "agent" in body:
                case_event(cur, case_id, "case_edit",
                           f"Agent set to {row['agent_name'] or '(cleared)'}")

            agent_os = lookup_agent_os(cur, row["agent_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = row_to_case(row)
    data["agentOs"] = agent_os
    return jsonify({"status": "success", "data": data})


@bp.route("/api/v1/incidents/from-alert/<int:alert_id>", methods=["POST"])
@login_required
def api_incident_from_alert(alert_id):
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

            case_ref = next_case_ref(cur)
            title    = (a["description"] or "Detection")[:120]
            desc     = a["description"] or ""

            cur.execute("""
                INSERT INTO cases (
                    case_ref, status, severity, threat_type, playbook_key, mode,
                    agent_name, agent_ip, source_ip, target_user,
                    title, description, assigned_to, data_categories,
                    persons_affected, cur_step, total_steps
                ) VALUES (
                    %s, 'investigating', %s, %s, %s, 'assisted',
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

            case_event(cur, new_row["id"], "opened",
                       f"Case {case_ref} opened from detection {alert_id}", actor="System")
            audit(cur, "Case opened from detection", case_ref,
                  f"Alert #{alert_id} — {title}")

            cur.execute("SELECT * FROM cases WHERE id = %s", (new_row["id"],))
            full = cur.fetchone()
            agent_os = lookup_agent_os(cur, full["agent_name"])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    data = row_to_case(full)
    data["agentOs"] = agent_os
    return jsonify({"status": "success", "data": data}), 201


# ── Step execution ────────────────────────────────────
@bp.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/run", methods=["POST"])
@login_required
def api_step_run(case_id, step_num):
    body     = request.get_json(silent=True) or {}
    platform = (body.get("platform") or "linux").lower()
    if platform not in ("windows", "linux"):
        return jsonify({"status": "error", "error": "platform must be 'windows' or 'linux'"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cur.fetchone()
            if not case:
                return jsonify({"status": "error", "error": "case not found"}), 404

            pb = PLAYBOOKS.get(case["playbook_key"] or "")
            if not pb or step_num < 0 or step_num >= len(pb["steps"]):
                return jsonify({"status": "error", "error": "step not found"}), 404

            step = pb["steps"][step_num]
            command = step.get(platform) or ""
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    if not command.strip():
        return jsonify({
            "status": "error",
            "error": f"step has no command for platform '{platform}'",
        }), 400

    agent_name = case["agent_name"]
    if not agent_name:
        return jsonify({"status": "error", "error": "case has no agent_name set"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT ip, port FROM agents WHERE name = %s", (agent_name,))
            row = cur.fetchone()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    if not row or not row["ip"]:
        return jsonify({
            "status": "error",
            "error": f"agent {agent_name!r} is not registered in the agents table",
        }), 404

    agent_ip   = str(row["ip"])
    agent_port = int(row["port"] or 5055)

    try:
        result = send_command(
            host=agent_ip,
            port=agent_port,
            target_os=platform,
            command=command,
            timeout=65,
        )
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"could not reach {agent_name} at {agent_ip}:{agent_port}: {e}",
        }), 502

    executed_by = session.get("display_name") or session.get("username") or "IT Team"
    try:
        with get_conn() as conn, conn.cursor() as cur:
            ok_verb = "ok" if result.get("ok") else "failed"
            case_event(cur, case_id, "step_run",
                       f"Step {step_num + 1} executed on {agent_name} ({ok_verb})",
                       actor=executed_by)
            audit(cur, "Step executed", case["case_ref"],
                  f"Step {step_num + 1} on {agent_name}: "
                  f"{(result.get('status') or ok_verb)[:200]}",
                  actor=executed_by)

            combined = result.get("stdout") or ""
            if result.get("stderr"):
                combined = (combined + "\n\nSTDERR:\n" + result["stderr"]).strip()
            if combined:
                filename = f"step{step_num + 1}_output.txt"
                cur.execute(
                    "INSERT INTO case_evidence (case_id, filename, kind, notes, uploaded_by) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (case_id, filename, "Agent Output", combined[:8000], executed_by),
                )
                case_event(cur, case_id, "evidence",
                           f"Evidence attached — {filename}", actor=executed_by)
    except Exception:
        pass

    return jsonify({"status": "success", "data": {
        "ok":         bool(result.get("ok")),
        "returncode": result.get("returncode"),
        "stdout":     result.get("stdout") or "",
        "stderr":     result.get("stderr") or "",
        "agent":      agent_name,
        "command":    command,
        "platform":   platform,
    }})


@bp.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/complete", methods=["POST"])
@login_required
def api_step_complete(case_id, step_num):
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
            case_event(cur, case_id, "step_done",
                       f"Step {step_num + 1} completed — {step_title}")
            audit(cur, "Playbook step completed", case["case_ref"],
                  f"Step {step_num + 1}: {step_title}")
            if new_step >= case["total_steps"]:
                case_event(cur, case_id, "status_change",
                           "All steps complete — case moved to Contained")
                audit(cur, "Playbook completed", case["case_ref"],
                      "All response steps completed")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": row_to_case(updated)})


@bp.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/undo", methods=["POST"])
@login_required
def api_step_undo(case_id, step_num):
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
            case_event(cur, case_id, "step_undo",
                       f"Step {step_num + 1} undone — {step_title}")
            audit(cur, "Playbook step undone", case["case_ref"],
                  f"Step {step_num + 1}")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "success", "data": row_to_case(updated)})


@bp.route("/api/v1/incidents/<int:case_id>/steps/<int:step_num>/preview", methods=["GET"])
@login_required
def api_step_preview(case_id, step_num):
    platform = (request.args.get("platform") or "linux").lower()
    if platform not in ("windows", "linux"):
        return jsonify({"status": "error", "error": "platform must be 'windows' or 'linux'"}), 400

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return jsonify({"status": "error", "error": "case not found"}), 404

    pb = PLAYBOOKS.get(case["playbook_key"] or "")
    if not pb or step_num < 0 or step_num >= len(pb["steps"]):
        return jsonify({"status": "error", "error": "step not found"}), 404

    raw_cmd = pb["steps"][step_num].get(platform) or ""
    cmd = (
        raw_cmd
        .replace("[ATTACKER_IP]", case["source_ip"] or "[ATTACKER_IP]")
        .replace("[username]", case["target_user"] or "[username]")
    )
    return jsonify({
        "status": "success",
        "data": {
            "platform": platform,
            "command": cmd,
            "agent": case["agent_name"],
            "mode": case["mode"] if "mode" in case.keys() else "assisted",
        },
    })


# ── Evidence ──────────────────────────────────────────
@bp.route("/api/v1/incidents/<int:case_id>/evidence", methods=["POST"])
@login_required
def api_case_evidence_add(case_id):
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

            case_event(cur, case_id, "evidence",
                       f"Evidence attached — {filename}", actor=actor)
            audit(cur, "Evidence attached", row["case_ref"], filename, actor=actor)
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