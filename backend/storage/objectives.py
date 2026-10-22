"""Persistence of the portfolio objectives."""

from __future__ import annotations

from typing import Any

from backend.portfolio.objectives import DEFAULTS
from backend.storage import portfolio_settings

_KEY = "objectives"


def load() -> dict[str, Any]:
    """The configured objectives, with defaults for any never set."""
    stored = portfolio_settings.load(_KEY)
    return {name: stored.get(name, default) for name, default in DEFAULTS.items()}


def save(objectives: dict[str, Any]) -> None:
    portfolio_settings.save(_KEY, objectives)
