"""Flask application factory wiring for SecGuard routes and middleware."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.config import settings
from backend.security import github_auth
from backend.storage.scans import application_exists, load_application
from backend.route_applications import register_routes as register_application_routes
from backend.route_discovery import register_routes as register_discovery_routes
from backend.route_frontend import register_routes as register_frontend_routes
from backend.route_models import register_routes as register_model_routes
from backend.route_repositories import register_routes as register_repository_routes

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
MAX_MODEL_BYTES = 25 * 1024 * 1024


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


app = Flask(__name__)
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


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=os.environ.get("SECGUARD_DEBUG") == "1",
    )
