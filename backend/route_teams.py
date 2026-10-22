"""Teams and business units API."""

from __future__ import annotations

from flask import jsonify, request

from backend.portfolio.applications import application_name, latest_repository_scans
from backend.portfolio.teams import clean
from backend.route_objectives import can_edit
from backend.security import github_auth
from backend.storage import teams as team_store


def _visible_keys() -> set[str] | None:
    """Application keys the caller may see, or None for everything."""
    if can_edit() or not github_auth.enabled():
        return None
    user = github_auth.current_user()
    return github_auth.readable_keys(user) if user else set()


def _payload() -> dict:
    editor = can_edit()
    visible = _visible_keys()
    teams = []
    for team in team_store.load():
        applications = [key for key in team.get("applications", []) if visible is None or key in visible]
        teams.append({**team, "applications": applications, "members": team.get("members", []) if editor else []})
    latest = latest_repository_scans()
    choices = [{"key": key, "name": application_name(key, scan)} for key, scan in sorted(latest.items())] if editor else []
    return {"success": True, "teams": teams, "applications": choices, "can_edit": editor}


def register_routes(app):
    @app.get("/api/teams")
    def get_teams():
        if github_auth.enabled() and github_auth.current_user() is None and not can_edit():
            return jsonify({"success": False, "error": "Sign in with GitHub to see the teams."}), 401
        return jsonify(_payload())

    @app.put("/api/teams")
    def put_teams():
        if not can_edit():
            return jsonify({"success": False, "error": "Only SecGuard administrators can change teams."}), 403
        teams, problem = clean(request.get_json(silent=True))
        if problem:
            return jsonify({"success": False, "error": problem}), 400
        team_store.save(teams)
        return jsonify(_payload())
