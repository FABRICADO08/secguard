"""Persistence of the portfolio objectives."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from backend.portfolio.objectives import DEFAULTS
from backend.storage import db, scans

_lock = threading.Lock()

_KEY = "objectives"


def _path() -> Path:
    return scans.APPLICATIONS_DIR.parent / "objectives.json"


def _init_schema(connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_settings (
                key TEXT PRIMARY KEY,
                data JSONB NOT NULL
            )
            """
        )


def _stored() -> dict[str, Any]:
    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT data FROM portfolio_settings WHERE key = %s", (_KEY,))
            row = cursor.fetchone()
        return db._as_dict(row[0]) if row else {}
    try:
        stored = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return stored if isinstance(stored, dict) else {}


def load() -> dict[str, Any]:
    """The configured objectives, with defaults for any never set."""
    stored = _stored()
    return {name: stored.get(name, default) for name, default in DEFAULTS.items()}


def save(objectives: dict[str, Any]) -> None:
    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO portfolio_settings (key, data) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data
                """,
                (_KEY, objectives),
            )
        return
    with _lock:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(objectives, indent=2), encoding="utf-8")
        temporary.replace(path)
