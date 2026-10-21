"""Portfolio objectives API."""

from __future__ import annotations

from flask import jsonify, request

from backend.config import settings
from backend.portfolio.objectives import CATALOGUE, clean
from backend.security import github_auth
from backend.security.auth import request_is_authorized
from backend.storage import objectives as objective_store


def can_edit() -> bool:
    """Deployment administrators: the API token holder or a login in SECGUARD_ADMINS."""
    if request_is_authorized():
        return True
    user = github_auth.current_user() if github_auth.enabled() else None
    return user is not None and user.login.lower() in settings.ADMINS


def _signed_out():
    return github_auth.enabled() and github_auth.current_user() is None


def _payload():
    return {
        "success": True,
        "objectives": objective_store.load(),
        "catalogue": {name: {"label": label, "kind": kind, "min": low, "max": high} for name, (label, kind, low, high) in CATALOGUE.items()},
        "can_edit": can_edit(),
    }


def register_routes(app):
    @app.get("/api/objectives")
    def get_objectives():
        if _signed_out():
            return jsonify({"success": False, "error": "Sign in with GitHub to see the objectives."}), 401
        return jsonify(_payload())

    @app.put("/api/objectives")
    def put_objectives():
        if not can_edit():
            return jsonify({"success": False, "error": "Only SecGuard administrators can change objectives."}), 403
        objectives, problem = clean(request.get_json(silent=True))
        if problem:
            return jsonify({"success": False, "error": problem}), 400
        objective_store.save(objectives)
        return jsonify(_payload())
