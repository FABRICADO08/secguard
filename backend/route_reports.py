"""HTTP routes for alerts, the weekly digest and PDF reports."""

from __future__ import annotations

import re

from flask import Response, jsonify, request

from backend.notifications import alerts
from backend.notifications.channels import Message, configured, send
from backend.portfolio.applications import application_name, latest_repository_scans
from backend.portfolio.objectives import evaluate
from backend.reports.digest import digest_message, digest_rows
from backend.reports.documents import application_report, portfolio_report
from backend.route_objectives import _signed_out, can_edit
from backend.security import github_auth
from backend.storage import objectives as objective_store
from backend.storage import teams as team_store
from backend.storage.scans import application_exists, load_application

_SIGN_IN = "Sign in with GitHub to continue."
_ADMIN_ONLY = "Only SecGuard administrators can send alerts and digests."
_NO_CHANNEL = "No alert channel is configured. Set a Slack or Teams webhook or SMTP settings on the server."


def _pdf(content: bytes, name: str) -> Response:
    filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "secguard"
    return Response(
        content,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )


def _summary_scan(summary: dict) -> dict:
    return {key: summary.get(key) for key in ("severity_counts", "maintainability", "health")}


def _deliver(message: Message):
    if not can_edit():
        return jsonify({"success": False, "error": _ADMIN_ONLY}), 403
    if not any(configured().values()):
        return jsonify({"success": False, "error": _NO_CHANNEL}), 409
    results = send(message)
    success = all(result == "sent" for result in results.values())
    return jsonify({"success": success, "results": results}), 200 if success else 502


def _register_alert_routes(app):
    @app.get("/api/alerts")
    def alert_settings():
        if _signed_out() and not can_edit():
            return jsonify({"success": False, "error": _SIGN_IN}), 401
        return jsonify(
            {
                "success": True,
                "channels": configured(),
                "min_severity": alerts.threshold(),
                "can_edit": can_edit(),
            }
        )

    @app.post("/api/alerts/test")
    def test_alert():
        return _deliver(
            Message(
                title="SecGuard test alert",
                lines=["Alerts from this SecGuard server reach this channel."],
            )
        )

    @app.post("/api/reports/digest")
    def send_digest():
        if not can_edit():
            return jsonify({"success": False, "error": _ADMIN_ONLY}), 403
        return _deliver(digest_message(digest_rows()))


def _register_pdf_routes(app):
    @app.get("/api/applications/<application_id>/report.pdf")
    def application_pdf(application_id: str):
        if not application_exists(application_id):
            return jsonify({"success": False, "error": "Application not found."}), 404
        application = load_application(application_id)
        repository = github_auth.repository_name(application)
        name = application_name(repository, application) if repository else str(application.get("name") or application_id)
        return _pdf(application_report(name, application, objective_store.load()), f"{name}-secguard-report")

    @app.get("/api/reports/portfolio.pdf")
    def portfolio_pdf():
        latest = latest_repository_scans()
        if github_auth.enabled():
            user = github_auth.current_user()
            if user is None:
                return jsonify({"success": False, "error": _SIGN_IN}), 401
            keys = sorted(github_auth.readable_keys(user))
        else:
            keys = list(latest)
        group, title = _report_group(request.args.get("team"), request.args.get("unit"))
        if group is None:
            return jsonify({"success": False, "error": "Team or business unit not found."}), 404
        rows = _portfolio_rows([key for key in keys if group == {"*"} or key in group], latest)
        return _pdf(portfolio_report(rows, title), "secguard-portfolio-report")


def _report_group(team_id: str | None, unit: str | None) -> tuple[set[str] | None, str]:
    """Application keys of the requested team or business unit ({"*"} for all) and the report title."""
    if not team_id and not unit:
        return {"*"}, "Portfolio report"
    field, value = ("id", team_id) if team_id else ("business_unit", unit)
    teams = [team for team in team_store.load() if team.get(field) == value]
    if not teams:
        return None, ""
    label = teams[0]["name"] if team_id else unit
    return {key for team in teams for key in team["applications"]}, f"{label} portfolio report"


def _portfolio_rows(keys: list[str], latest: dict[str, dict]) -> list[dict]:
    objectives = objective_store.load()
    rows = []
    for key in keys:
        summary = latest.get(key)
        scan = _summary_scan(summary) if summary else None
        rows.append(
            {
                "name": application_name(key, summary),
                "scan": scan,
                "objectives": evaluate(objectives, scan) if scan else {"met": None, "results": []},
            }
        )
    rows.sort(key=lambda row: (row["scan"] is None, row["name"].lower()))
    return rows


def register_report_routes(app):
    _register_alert_routes(app)
    _register_pdf_routes(app)
