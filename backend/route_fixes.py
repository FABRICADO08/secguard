"""HTTP routes that open GitHub pull requests upgrading vulnerable dependencies."""

from __future__ import annotations

from flask import jsonify

from backend.repository.fix_pull_request import (
    MESSAGES,
    FixError,
    FixRequest,
    open_fix_pull_request,
)
from backend.repository.upgrades import plan_upgrades
from backend.security import github_auth
from backend.security.rate_limit import rate_limited
from backend.storage.scans import application_exists, load_application

_NOT_FOUND = ({"success": False, "error": "Application not found."}, 404)


def _repository_application(application_id: str) -> dict | None:
    if not application_exists(application_id):
        return None
    application = load_application(application_id)
    return application if application.get("platform") == "Repository" else None


def _writable(application: dict) -> tuple[github_auth.GitHubUser | None, dict | None, tuple | None]:
    user = github_auth.current_user() if github_auth.enabled() else None
    if user is None or not user.token:
        return None, None, ({"success": False, "error": "Sign in with GitHub to open a fix pull request."}, 401)
    repository = user.repositories.get(github_auth.repository_name(application).lower())
    if not (repository or {}).get("can_trigger"):
        return None, None, ({"success": False, "error": "Opening a fix pull request needs write access to the repository."}, 403)
    return user, repository, None


def _open(application_id: str, application: dict):
    user, repository, error = _writable(application)
    if error:
        return jsonify(error[0]), error[1]
    upgrades = plan_upgrades(application.get("repository"))
    if not upgrades:
        return jsonify({"success": False, "error": "No vulnerable dependency can be upgraded automatically."}), 409
    fix = FixRequest(
        token=user.token,
        repository=repository["name"],
        base=repository["default_branch"],
        branch=f"secguard/upgrade-vulnerable-{application_id[:12]}",
    )
    try:
        result = open_fix_pull_request(fix, upgrades)
    except FixError as failure:
        message, status = MESSAGES.get(failure.reason, MESSAGES["refused"])
        return jsonify({"success": False, "error": message}), status
    except github_auth.requests.RequestException:
        return jsonify({"success": False, "error": "Could not reach GitHub."}), 502
    return jsonify({"success": True, **result}), 201


def register_routes(app):
    @app.get("/api/applications/<application_id>/fix-pull-request")
    def fix_pull_request_plan(application_id: str):
        """List the upgrades a fix pull request would make."""
        application = _repository_application(application_id)
        if application is None:
            return jsonify(_NOT_FOUND[0]), _NOT_FOUND[1]
        upgrades = plan_upgrades(application.get("repository"))
        return jsonify({"success": True, "upgrades": [item.to_dict() for item in upgrades]})

    @app.post("/api/applications/<application_id>/fix-pull-request")
    @rate_limited
    def open_fix_pull_request_route(application_id: str):
        """Open a pull request upgrading every rewritable vulnerable dependency."""
        application = _repository_application(application_id)
        if application is None:
            return jsonify(_NOT_FOUND[0]), _NOT_FOUND[1]
        return _open(application_id, application)
