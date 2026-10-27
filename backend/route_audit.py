"""Audit trail of state-changing requests, with JSON and CSV export for administrators."""

from __future__ import annotations

import csv
import io
import logging
import time
from datetime import UTC, datetime

from flask import Response, jsonify, request

from backend.config import settings
from backend.route_objectives import can_edit
from backend.security import github_auth
from backend.security.auth import presented_key, request_is_authorized
from backend.storage import audit

LOG = logging.getLogger(__name__)

AUDITED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Signing in is a GET, but who signed in and when belongs in the trail.
AUDITED_PATHS = frozenset({"/auth/github/callback"})

UNROUTED_PATH = "(no matching route)"

DEFAULT_LIMIT = 200

MAX_LIMIT = 5000

CSV_COLUMNS = ("time", "actor", "method", "path", "status", "address")


def actor() -> str:
    user = github_auth.current_user() if github_auth.enabled() else None
    if user is not None:
        return f"github:{user.login}"
    key = presented_key()
    if key is not None:
        return f"api-key:{key['id']}"
    if request_is_authorized():
        return "api-token" if settings.API_TOKEN else "local"
    return "anonymous"


def _time(at: float) -> str:
    return datetime.fromtimestamp(at, tz=UTC).isoformat(timespec="seconds")


def _limit() -> int:
    try:
        value = int(request.args.get("limit", DEFAULT_LIMIT))
    except ValueError:
        value = DEFAULT_LIMIT
    return max(1, min(value, MAX_LIMIT))


def _cell(value) -> str:
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def record_request(response):
    """Write one audit entry per state-changing request; never fail the response."""
    if request.method not in AUDITED_METHODS and request.path not in AUDITED_PATHS:
        return response

    try:
        audit.record(
            {
                "at": time.time(),
                "actor": actor(),
                "method": request.method,
                # Unrouted paths are free text a caller chose, so they are not stored.
                "path": request.path if request.url_rule is not None else UNROUTED_PATH,
                "status": response.status_code,
                "address": request.remote_addr or "",
            }
        )
    except Exception as error:  # noqa: BLE001 - the action already happened; losing the response would hide it
        LOG.error("Could not write audit entry (%s)", type(error).__name__)

    return response


def _forbidden():
    return jsonify({"success": False, "error": "Only SecGuard administrators can read the audit log."}), 403


def register_routes(app):
    app.after_request(record_request)

    @app.get("/api/audit")
    def audit_log():
        if not can_edit():
            return _forbidden()
        entries = [{**entry, "time": _time(entry["at"])} for entry in audit.recent(_limit())]
        return jsonify({"success": True, "entries": entries})

    @app.get("/api/audit.csv")
    def audit_log_csv():
        if not can_edit():
            return _forbidden()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(CSV_COLUMNS)
        for entry in audit.recent(_limit()):
            row = {**entry, "time": _time(entry["at"])}
            writer.writerow([_cell(row[column]) for column in CSV_COLUMNS])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=secguard-audit.csv"},
        )
