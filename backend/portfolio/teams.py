"""Teams and business units: named groups of applications with member logins who may read them."""

from __future__ import annotations

import re
from typing import Any

MAX_TEAMS = 200
MAX_ITEMS = 500
MAX_LABEL = 80
_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")
_APPLICATION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _label(value: object) -> str:
    return re.sub(r"\s+", " ", value).strip() if isinstance(value, str) else ""


def team_id(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "team"


def _strings(value: object, pattern: re.Pattern[str], what: str) -> tuple[list[str], str]:
    if value is None:
        return [], ""
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        return [], f"{what} must be a list of at most {MAX_ITEMS} entries."
    items = [item.strip().lower() for item in value if isinstance(item, str)]
    if not all(pattern.match(item) for item in items) or len(items) != len(value):
        example = "owner/name" if pattern is _APPLICATION else "a GitHub login"
        return [], f"Every entry in {what.lower()} must look like {example}."
    return sorted(set(items)), ""


def _clean_team(raw: object) -> tuple[dict[str, Any], str]:
    if not isinstance(raw, dict):
        return {}, "Each team must be an object."
    name, unit = _label(raw.get("name")), _label(raw.get("business_unit"))
    if not name or len(name) > MAX_LABEL or len(unit) > MAX_LABEL:
        return {}, f"Each team needs a name, and names and business units can have at most {MAX_LABEL} characters."
    applications, problem = _strings(raw.get("applications"), _APPLICATION, "Applications")
    members, member_problem = _strings(raw.get("members"), _LOGIN, "Members")
    if problem or member_problem:
        return {}, problem or member_problem
    return {"id": team_id(name), "name": name, "business_unit": unit, "applications": applications, "members": members}, ""


def clean(payload: object) -> tuple[list[dict[str, Any]], str]:
    """Validated teams from an API payload ``{"teams": [...]}``, or a problem description."""
    raw = payload.get("teams") if isinstance(payload, dict) else None
    if not isinstance(raw, list) or len(raw) > MAX_TEAMS:
        return [], f"Send {{\"teams\": [...]}} with at most {MAX_TEAMS} teams."
    teams = []
    for entry in raw:
        team, problem = _clean_team(entry)
        if problem:
            return [], problem
        teams.append(team)
    ids = [team["id"] for team in teams]
    if len(ids) != len(set(ids)):
        return [], "Team names must be unique."
    return sorted(teams, key=lambda team: team["name"].lower()), ""


def granted(login: str, teams: list[dict[str, Any]]) -> set[str]:
    """Application keys a GitHub login may read because it is a member of their team."""
    login = login.lower()
    return {key for team in teams if login in team.get("members", []) for key in team.get("applications", [])}


def teams_for(key: str, teams: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"id": team["id"], "name": team["name"], "business_unit": team.get("business_unit", "")}
        for team in teams
        if key.lower() in team.get("applications", [])
    ]
