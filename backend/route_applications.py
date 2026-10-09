"""HTTP routes for application records, findings, and rule catalogues."""

from flask import jsonify, request, current_app

from backend.model.normalized import platform_model_statistics
from backend.platforms.mendix.findings import RULE_CATALOGUE as MENDIX_RULE_CATALOGUE
from backend.platforms.outsystems.findings import (
    RULE_CATALOGUE as OUTSYSTEMS_RULE_CATALOGUE,
)
from backend.portfolio.summary import portfolio_summary
from backend.repository.findings import RULE_CATALOGUE as REPOSITORY_RULE_CATALOGUE
from backend.risk.scoring import summarize
from backend.rules.engine import default_rules
from backend.security import github_auth
from backend.security.auth import require_api_token
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
        findings = load_findings(application_id)
        filters = {
            key: str(request.args.get(key)).lower()
            for key in ("severity", "category", "platform", "rule_id")
            if request.args.get(key)
        }
        for key, value in filters.items():
            findings = [
                finding
                for finding in findings
                if str(finding.get(key, "")).lower() == value
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
        for finding in load_findings(application_id):
            if finding.get("id") == finding_id:
                return jsonify({"success": True, "finding": finding})
        return jsonify({"success": False, "error": "Finding not found."}), 404


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
    _register_rules_route(app)
