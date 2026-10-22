"""Persistence of teams and business units."""

from __future__ import annotations

from typing import Any

from backend.storage import portfolio_settings

_KEY = "teams"


def load() -> list[dict[str, Any]]:
    teams = portfolio_settings.load(_KEY).get("teams")
    return [team for team in teams if isinstance(team, dict)] if isinstance(teams, list) else []


def save(teams: list[dict[str, Any]]) -> None:
    portfolio_settings.save(_KEY, {"teams": teams})
