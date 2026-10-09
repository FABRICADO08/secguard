"""Frontend page-serving routes and sign-in redirects."""

from flask import jsonify, redirect, request, send_from_directory
from urllib.parse import urlencode

from backend.security import github_auth


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
