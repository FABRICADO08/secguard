"""Frontend page-serving routes and sign-in redirects."""

import logging
import os
import tempfile
from urllib.parse import urlencode

from flask import jsonify, redirect, request, send_from_directory

from backend.security import github_auth

LOG = logging.getLogger(__name__)


def sign_in_gate(page: str):
    """Require GitHub sign-in for frontend pages when OAuth is enabled."""
    if not github_auth.enabled() or not page.endswith(".html"):
        return None

    signed_in = github_auth.current_user() is not None
    if page == github_auth.LOGIN_PAGE:
        if signed_in:
            return redirect(github_auth.DEFAULT_LANDING)
        next_page = github_auth.safe_next(request.args.get("next", ""))
        return redirect("/auth/github/login?" + urlencode({"next": next_page}))

    if signed_in:
        return None
    return redirect(
        "/login.html?" + urlencode({"next": request.full_path.rstrip("?")})
    )


def register_routes(app, frontend):
    @app.get("/")
    def index():
        """Serve the scan landing page."""
        gate = sign_in_gate("index.html")
        if gate is not None:
            return gate
        return send_from_directory(frontend, "index.html")

    @app.get("/<path:path>")
    def frontend_files(path):
        """Serve a static frontend file or return a not-found response."""
        file_path = frontend / path
        gate = sign_in_gate(path)
        if gate is not None and file_path.is_file():
            return gate
        if file_path.is_file():
            return send_from_directory(frontend, path)
        return jsonify({"error": "Frontend resource not found."}), 404

    @app.get("/api/health/ready")
    def readiness():
        """Report whether storage is reachable, for load balancer health checks."""
        storage = "ok" if _storage_ready() else "unavailable"
        ready = storage == "ok"
        return jsonify({"status": "ready" if ready else "unavailable", "checks": {"storage": storage}}), (
            200 if ready else 503
        )

    @app.get("/api/health")
    def health():
        """Return the service health and version."""
        return jsonify(
            {
                "status": "ok",
                "service": "Application Security Platform",
                "version": "0.2.0",
            }
        )


def _writable(directory) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=directory) as probe:
        probe.write(b"readiness probe")
        probe.flush()
        os.fsync(probe.fileno())


def _storage_ready() -> bool:
    from backend.storage import audit, db, scans, sessions

    try:
        if db.use_database():
            db.ping()
        else:
            for directory in (scans.APPLICATIONS_DIR, sessions.SESSIONS_DIR, audit.AUDIT_FILE.parent):
                _writable(directory)
            # Opening for append writes nothing but fails when the log itself cannot be appended to.
            with audit.AUDIT_FILE.open("a", encoding="utf-8"):
                pass
        return True
    except Exception as error:  # noqa: BLE001 - any storage failure means not ready
        # The exception text can carry connection details, so only its type is logged.
        LOG.warning("Readiness check could not reach storage (%s)", type(error).__name__)
        return False
