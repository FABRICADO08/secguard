"""Flask application factory wiring for SecGuard routes and middleware."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.config import observability, settings
from backend.discovery.api_discovery import discover_common_api_paths
from backend.discovery.crawler import crawl
from backend.discovery.endpoints import discover_endpoints
from backend.discovery.fingerprint import TargetUnreachableError, fetch_application
from backend.discovery.technology import detect_technologies
from backend.platforms.mendix.service import analyze_model
from backend.route_applications import register_routes as register_application_routes
from backend.route_api_keys import register_routes as register_api_key_routes
from backend.route_audit import register_routes as register_audit_routes
from backend.route_discovery import register_routes as register_discovery_routes
from backend.route_fixes import register_routes as register_fix_routes
from backend.route_frontend import register_routes as register_frontend_routes
from backend.route_models import register_routes as register_model_routes
from backend.route_objectives import register_routes as register_objective_routes
from backend.route_reports import register_report_routes
from backend.route_repositories import register_routes as register_repository_routes
from backend.route_teams import register_routes as register_team_routes
from backend.route_tickets import register_routes as register_ticket_routes
from backend.scanners.configuration import scan_exposed_paths
from backend.security import github_auth
from backend.storage.scans import application_exists, load_application

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
MAX_MODEL_BYTES = 25 * 1024 * 1024

# Route modules look these up on this module at request time, so they can
# be replaced in one place (tests substitute network and analysis calls).
__all__ = [
    "MAX_MODEL_BYTES",
    "TargetUnreachableError",
    "analyze_model",
    "app",
    "crawl",
    "detect_technologies",
    "discover_common_api_paths",
    "discover_endpoints",
    "fetch_application",
    "scan_exposed_paths",
]


class _FirstForwardedValue:
    """Use the left-most forwarded protocol, host and port values."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        proto = environ.get("HTTP_X_FORWARDED_PROTO", "").split(",")[0].strip()
        if proto:
            environ["wsgi.url_scheme"] = proto
        host = environ.get("HTTP_X_FORWARDED_HOST", "").split(",")[0].strip()
        if host:
            environ["HTTP_HOST"] = environ["SERVER_NAME"] = host
        port = environ.get("HTTP_X_FORWARDED_PORT", "").split(",")[0].strip()
        if port:
            environ["SERVER_PORT"] = port
        return self.app(environ, start_response)


observability.configure_logging()
settings.check_production()

app = Flask(__name__)
observability.install(app)
app.secret_key = settings.SECRET_KEY or secrets.token_hex(32)

if settings.TRUST_FIRST_FORWARDED_VALUE:
    app.wsgi_app = _FirstForwardedValue(app.wsgi_app)
elif settings.PROXY_DEPTH > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=settings.PROXY_DEPTH,
        x_proto=settings.PROXY_DEPTH,
        x_host=settings.PROXY_DEPTH,
        x_port=settings.PROXY_DEPTH,
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=settings.SESSION_COOKIE_SECURE,
)
app.register_blueprint(github_auth.blueprint)


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


@app.after_request
def add_security_headers(response):
    """Harden every response against framing, MIME sniffing and injected scripts."""
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.before_request
def hide_inaccessible_applications():
    """Treat a repository the signed-in user cannot read as nonexistent."""
    application_id = (request.view_args or {}).get("application_id")
    if not application_id or not application_exists(application_id):
        return None
    if github_auth.can_view(load_application(application_id)):
        return None
    return jsonify({"success": False, "error": "Application not found."}), 404


register_frontend_routes(app, FRONTEND)
compatibility = sys.modules[__name__]
register_discovery_routes(app, compatibility)
register_model_routes(app, compatibility)
register_application_routes(app)
register_repository_routes(app, compatibility)
register_objective_routes(app)
register_report_routes(app)
register_team_routes(app)
register_ticket_routes(app)
register_fix_routes(app)
register_audit_routes(app)
register_api_key_routes(app)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=os.environ.get("SECGUARD_DEBUG") == "1",
    )
