"""Blueprint registration."""
from . import (
    auth, pages, alerts, systems, incidents,
    playbooks_routes, automation, reports, audit,
    analysis, metrics, settings,
)


def register_blueprints(app):
    for mod in (
        auth, pages, alerts, systems, incidents,
        playbooks_routes, automation, reports, audit,
        analysis, metrics, settings,
    ):
        app.register_blueprint(mod.bp)