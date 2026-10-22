"""Portfolio-wide settings documents (objectives, teams) in PostgreSQL or a JSON file."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from backend.storage import db, scans

_lock = threading.Lock()


def _path(key: str) -> Path:
    return scans.APPLICATIONS_DIR.parent / f"{key}.json"


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


def load(key: str) -> dict[str, Any]:
    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT data FROM portfolio_settings WHERE key = %s", (key,))
            row = cursor.fetchone()
        return db._as_dict(row[0]) if row else {}
    try:
        stored = json.loads(_path(key).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return stored if isinstance(stored, dict) else {}


def save(key: str, data: dict[str, Any]) -> None:
    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO portfolio_settings (key, data) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data
                """,
                (key, data),
            )
        return
    with _lock:
        path = _path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
