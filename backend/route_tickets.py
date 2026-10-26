"""HTTP routes for ticket sync with GitHub Issues, Jira and Azure DevOps."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from flask import jsonify, request

from backend.config import settings
from backend.portfolio import triage
from backend.portfolio.summary import finding_key
from backend.route_applications import _can_triage, _find
from backend.route_objectives import _signed_out, can_edit
from backend.security.rate_limit import rate_limited
from backend.storage import triage as triage_store
from backend.storage.findings import load_findings
from backend.storage.scans import (
    application_exists,
    list_applications,
    load_application,
)
from backend.tickets import sync
from backend.tickets.providers import PROVIDERS, TicketError, active, missing_settings

_WRITE_ACCESS = "You need write access to this application."
_NOT_CONFIGURED = "Ticket sync is not configured on this server."


def _settings_payload() -> dict:
    name = settings.TICKET_PROVIDER
    provider = PROVIDERS.get(name)
    return {
        "success": True,
        "provider": name if provider else "",
        "label": provider.label if provider else "",
        "configured": active() is not None,
        "missing": missing_settings(name) if name else [],
        "min_severity": settings.TICKET_MIN_SEVERITY if sync.auto_threshold() is not None else "none",
        "webhook": bool(settings.TICKET_WEBHOOK_SECRET) and name == "github",
        "can_edit": can_edit(),
    }


def _register_settings_routes(app):
    @app.get("/api/tickets")
    def ticket_settings():
        if _signed_out() and not can_edit():
            return jsonify({"success": False, "error": "Sign in with GitHub to continue."}), 401
        return jsonify(_settings_payload())

    @app.post("/api/tickets/sync")
    def sync_all_tickets():
        if not can_edit():
            return jsonify({"success": False, "error": "Only SecGuard administrators can sync every application."}), 403
        if active() is None:
            return jsonify({"success": False, "error": _NOT_CONFIGURED}), 409
        totals: dict[str, int] = {}
        seen: set[str] = set()
        for summary in list_applications():
            system = triage.system_key(summary)
            if system in seen:
                continue
            seen.add(system)
            latest = sync.latest_application_id(system)
            result = sync.sync_application(load_application(latest), load_findings(latest))
            for name, count in result.items():
                totals[name] = totals.get(name, 0) + count
        return jsonify({"success": True, "result": totals})


def _register_application_routes(app):
    @app.post("/api/applications/<application_id>/findings/<finding_id>/ticket")
    def open_finding_ticket(application_id: str, finding_id: str):
        if not application_exists(application_id):
            return jsonify({"success": False, "error": "Application not found."}), 404
        if not _can_triage(application_id):
            return jsonify({"success": False, "error": _WRITE_ACCESS}), 403
        if active() is None:
            return jsonify({"success": False, "error": _NOT_CONFIGURED}), 409
        finding = _find(application_id, finding_id)
        if finding is None:
            return jsonify({"success": False, "error": "Finding not found."}), 404
        application = load_application(application_id)
        try:
            sync.open_ticket(application, finding)
        except sync.TicketPending as error:
            return jsonify({"success": False, "error": str(error)}), 409
        except TicketError:
            sync.LOG.warning("Could not open a ticket for %s", finding_key(finding), exc_info=True)
            return jsonify({"success": False, "error": "The ticket could not be opened. The server log has the details."}), 502
        record = triage_store.load_system(triage.system_key(application)).get(finding_key(finding))
        today = datetime.now(timezone.utc).date()
        return jsonify({"success": True, "workflow": triage.workflow(finding, record, today)}), 201

    @app.post("/api/applications/<application_id>/tickets/sync")
    def sync_application_tickets(application_id: str):
        if not application_exists(application_id):
            return jsonify({"success": False, "error": "Application not found."}), 404
        if not _can_triage(application_id):
            return jsonify({"success": False, "error": _WRITE_ACCESS}), 403
        if active() is None:
            return jsonify({"success": False, "error": _NOT_CONFIGURED}), 409
        result = sync.sync_application(load_application(application_id), load_findings(application_id))
        return jsonify({"success": True, "result": result})


def _signature_valid(body: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(settings.TICKET_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _register_webhook_route(app):
    @app.post("/api/tickets/github/webhook")
    @rate_limited
    def github_issue_webhook():
        if not settings.TICKET_WEBHOOK_SECRET:
            return jsonify({"success": False, "error": "The ticket webhook is not configured."}), 404
        if not _signature_valid(request.get_data(), request.headers.get("X-Hub-Signature-256", "")):
            return jsonify({"success": False, "error": "Invalid signature."}), 401
        if request.headers.get("X-GitHub-Event") != "issues":
            return jsonify({"success": True, "applied": False})
        payload = request.get_json(silent=True) or {}
        return jsonify({"success": True, "applied": sync.apply_github_event(payload)})


def register_routes(app):
    _register_settings_routes(app)
    _register_application_routes(app)
    _register_webhook_route(app)



