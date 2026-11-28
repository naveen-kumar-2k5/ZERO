"""UI page renderers (templates live in the Flask app's templates/ folder)."""
from flask import Blueprint, render_template

from ..helpers import login_required


bp = Blueprint("pages", __name__)


@bp.route("/")
@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@bp.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@bp.route("/health")
@login_required
def health_page():
    return render_template("health.html")


@bp.route("/systems")
@login_required
def systems_page():
    return render_template("systems.html")


@bp.route("/incidents")
@login_required
def incidents_page():
    return render_template("incidents.html")


@bp.route("/incidents/<int:case_id>")
@login_required
def incident_detail_page(case_id):
    return render_template("case_detail.html", case_id=case_id)


@bp.route("/report")
@login_required
def report_page():
    return render_template("report.html")


@bp.route("/playbooks")
@login_required
def playbooks_page():
    return render_template("playbooks.html")


@bp.route("/audit")
@login_required
def audit_page():
    return render_template("audit.html")


@bp.route("/analysis")
@login_required
def analysis_page():
    return render_template("analysis.html")


@bp.route("/metrics")
@login_required
def metrics_page():
    return render_template("metrics.html")


@bp.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")


@bp.route("/settings/users")
@login_required
def users_page():
    return render_template("users.html")