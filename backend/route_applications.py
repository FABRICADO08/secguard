"""HTTP routes for application records, findings, and rule catalogues."""

from datetime import datetime, timezone

from flask import current_app, jsonify, request

from backend.model.normalized import platform_model_statistics
from backend.platforms.mendix.findings import RULE_CATALOGUE as MENDIX_RULE_CATALOGUE
from backend.platforms.outsystems.findings import (
    RULE_CATALOGUE as OUTSYSTEMS_RULE_CATALOGUE,
)
from backend.portfolio import triage
from backend.portfolio.summary import finding_key, portfolio_summary
from backend.repository.findings import RULE_CATALOGUE as REPOSITORY_RULE_CATALOGUE
from backend.risk.scoring import summarize
from backend.rules.engine import default_rules
from backend.security import github_auth
from backend.security.auth import request_is_authorized, require_api_token
from backend.storage import triage as triage_store
from backend.storage.findings import load_findings
from backend.storage.scans import (
    application_exists,
    delete_application,
    list_applications,
    load_application,
)


def _platform_rules(platform: str, catalogue: dict) -> list[dict]:
    """Convert platform catalogue metadata into API response records."""
    return [
        {
            "id": rule_id,
            "title": metadata["title"],
            "severity": "",
            "category": metadata["category"],
            "confidence": metadata["confidence"],
            "platform": platform,
            "cwe": metadata["cwe"],
            "owasp": metadata["owasp"],
            "description": "",
            "recommendation": "",
        }
        for rule_id, metadata in catalogue.items()
    ]


def _register_application_list_routes(app):
    @app.get("/api/applications")
    def applications():
        """List application summaries visible to the current user."""
        return jsonify(
            {
                "success": True,
                "applications": github_auth.visible(list_applications()),
            }
        )

    @app.get("/api/portfolio/summary")
    def portfolio():
        """Return summary metrics for all visible applications."""
        return jsonify(
            {
                "success": True,
                **portfolio_summary(
                    github_auth.visible(list_applications()), load_findings
                ),
            }
        )


def _register_application_detail_routes(app):
    @app.get("/api/applications/<application_id>")
    def get_application(application_id: str):
        """Return one stored application and its model statistics."""
        if not application_exists(application_id):
            return jsonify(
                {"success": False, "error": "Application not found."}
            ), 404
        try:
            application = load_application(application_id)
            return jsonify(
                {
                    "success": True,
                    "application": application,
                    "model_statistics": platform_model_statistics(
                        application.get("platform", ""), application.get("model", {})
                    ),
                }
            )
        except Exception:
            current_app.logger.exception("Could not load application.")
            return jsonify(
                {"success": False, "error": "Could not load application."}
            ), 500


def _register_finding_routes(app):
    @app.delete("/api/applications/<application_id>")
    @require_api_token
    def remove_application(application_id: str):
        """Delete an application and its persisted findings."""
        if not delete_application(application_id):
            return jsonify(
                {"success": False, "error": "Application not found."}
            ), 404
        return jsonify({"success": True, "application_id": application_id})

    @app.get("/api/applications/<application_id>/findings")
    def application_findings(application_id: str):
        """List an application's findings with optional filters."""
        if not application_exists(application_id):
            return jsonify(
                {"success": False, "error": "Application not found."}
            ), 404
        findings = _with_workflow(application_id)
        filters = {
            key: str(request.args.get(key)).lower()
            for key in ("severity", "category", "platform", "rule_id", "status")
            if request.args.get(key)
        }
        for key, value in filters.items():
            findings = [
                finding
                for finding in findings
                if _field(finding, key).lower() == value
            ]
        return jsonify(
            {
                "success": True,
                "application_id": application_id,
                "filters": filters,
                "summary": summarize(findings),
                "findings": findings,
            }
        )

    @app.get("/api/applications/<application_id>/findings/<finding_id>")
    def application_finding(application_id: str, finding_id: str):
        """Return a finding from the requested application."""
        if not application_exists(application_id):
            return jsonify(
                {"success": False, "error": "Application not found."}
            ), 404
        finding = _find(application_id, finding_id)
        if finding is None:
            return jsonify({"success": False, "error": "Finding not found."}), 404
        return jsonify(
            {"success": True, "finding": finding, "can_edit": _can_triage(application_id)}
        )


def _register_workflow_route(app):
    @app.put("/api/applications/<application_id>/findings/<finding_id>/workflow")
    def update_finding_workflow(application_id: str, finding_id: str):
        """Record a status, owner, due date or reason change on a finding."""
        if not application_exists(application_id):
            return jsonify({"success": False, "error": "Application not found."}), 404
        if not _can_triage(application_id):
            return jsonify(
                {"success": False, "error": "You need write access to this application."}
            ), 403
        finding = _find(application_id, finding_id)
        if finding is None:
            return jsonify({"success": False, "error": "Finding not found."}), 404
        system = triage.system_key(load_application(application_id))
        key = finding_key(finding)
        previous = triage_store.load_system(system).get(key, {})
        update, problem = triage.clean_update(request.get_json(silent=True), previous)
        if problem:
            return jsonify({"success": False, "error": problem}), 400
        record = triage.apply_update(previous, update, _actor())
        triage_store.save_record(system, key, record)
        today = datetime.now(timezone.utc).date()
        return jsonify(
            {"success": True, "workflow": triage.workflow(finding, record, today)}
        )


def _with_workflow(application_id: str) -> list[dict]:
    system = triage.system_key(load_application(application_id))
    return triage.annotate(load_findings(application_id), triage_store.load_system(system))


def _find(application_id: str, finding_id: str) -> dict | None:
    return next(
        (item for item in _with_workflow(application_id) if item.get("id") == finding_id),
        None,
    )


def _field(finding: dict, key: str) -> str:
    if key == "status":
        return str(finding["workflow"]["status"])
    return str(finding.get(key, ""))


def _actor() -> str:
    user = github_auth.current_user() if github_auth.enabled() else None
    return user.login if user else "administrator"


def _can_triage(application_id: str) -> bool:
    """Deployment administrators, or GitHub users who can push to the repository."""
    application = load_application(application_id)
    user = github_auth.current_user() if github_auth.enabled() else None
    if user is not None and application.get("platform") == "Repository":
        name = github_auth.repository_name(application).lower()
        if (user.repositories.get(name) or {}).get("can_trigger"):
            return True
    return request_is_authorized()


def _register_rules_route(app):
    @app.get("/api/rules")
    def rules_catalogue():
        """Return generic and platform-specific rule definitions."""
        rules = [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "category": rule.category,
                "confidence": rule.confidence,
                "platform": rule.platform,
                "cwe": rule.cwe,
                "owasp": rule.owasp,
                "description": rule.description,
                "recommendation": rule.recommendation,
            }
            for rule in default_rules()
        ]
        rules.extend(_platform_rules("Mendix", MENDIX_RULE_CATALOGUE))
        rules.extend(_platform_rules("OutSystems", OUTSYSTEMS_RULE_CATALOGUE))
        rules.extend(
            _platform_rules(
                "Repository",
                {
                    rule_id: {**metadata, "confidence": ""}
                    for rule_id, metadata in REPOSITORY_RULE_CATALOGUE.items()
                },
            )
        )
        return jsonify({"success": True, "rules": rules})


def register_routes(app):
    _register_application_list_routes(app)
    _register_application_detail_routes(app)
    _register_finding_routes(app)
    _register_workflow_route(app)
    _register_rules_route(app)
