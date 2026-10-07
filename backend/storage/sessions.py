"""GitHub sign-in state shared by every worker and kept across restarts.

The OAuth handshake spans two requests that may land on different gunicorn
workers — and on Azure App Service the container is routinely restarted
between them — so the pending state/verifier and the signed-in sessions
cannot live in one process. They are kept in Postgres when DATABASE_URL is
configured and in JSON files under data/ otherwise, mirroring how scans and
findings are stored.

Session payloads include the GitHub token, so both backends sit on the
server side; the browser cookie only ever carries the random session id.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from backend.storage import db

ROOT = Path(__file__).resolve().parents[2]

SESSIONS_DIR = ROOT / "data" / "sessions"

_LOCK = threading.Lock()

# A login left half-finished stops being retryable after this long.
PENDING_TTL_SECONDS = 10 * 60


def _safe_key(key: str) -> str:
    return "".join(character if character.isalnum() or character in "-_" else "" for character in key)


def _path(kind: str, key: str) -> Path:
    return SESSIONS_DIR / f"{kind}-{_safe_key(key)}.json"


def _purge_expired(items: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    now = time.time()

    return {
        key: value
        for key, value in items.items()
        if float(value.get("expires", 0)) >= now
    }


# --------------------------------------------------------------------- files


def _read_file(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _file_put(kind: str, key: str, payload: dict[str, Any]) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    path = _path(kind, key)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload))
    temporary.replace(path)


def _file_pop(kind: str, key: str) -> dict[str, Any] | None:
    with _LOCK:
        path = _path(kind, key)

        if not path.exists():
            return None

        try:
            payload = _read_file(path)
        finally:
            path.unlink(missing_ok=True)

    if payload is None:
        return None

    if float(payload.get("expires", 0)) < time.time():
        return None

    return payload


def _file_get(kind: str, key: str) -> dict[str, Any] | None:
    payload = _read_file(_path(kind, key))

    if payload is None or float(payload.get("expires", 0)) < time.time():
        return None

    return payload


def _file_delete(kind: str, key: str) -> None:
    _path(kind, key).unlink(missing_ok=True)


def _file_prune() -> None:
    """Remove expired entries; called on writes so the directory stays small."""

    if not SESSIONS_DIR.is_dir():
        return

    now = time.time()

    for path in SESSIONS_DIR.glob("*.json"):
        payload = _read_file(path)

        if payload is None or float(payload.get("expires", 0)) < now:
            path.unlink(missing_ok=True)


# ------------------------------------------------------------------ postgres


def _init_schema(connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                kind TEXT NOT NULL,
                id TEXT NOT NULL,
                data JSONB NOT NULL,
                expires DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (kind, id)
            )
            """
        )


def _db_put(kind: str, key: str, payload: dict[str, Any]) -> None:
    with db._connection(init=_init_schema) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM sessions WHERE expires < %s",
                (time.time(),),
            )
            cursor.execute(
                """
                INSERT INTO sessions (kind, id, data, expires)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (kind, id) DO UPDATE
                SET data = EXCLUDED.data, expires = EXCLUDED.expires
                """,
                (kind, key, payload, float(payload.get("expires", 0))),
            )


def _db_pop(kind: str, key: str) -> dict[str, Any] | None:
    with db._connection(init=_init_schema) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM sessions WHERE kind = %s AND id = %s RETURNING data, expires",
                (kind, key),
            )
            row = cursor.fetchone()

    if row is None or float(row[1]) < time.time():
        return None

    return db._as_dict(row[0])


def _db_get(kind: str, key: str) -> dict[str, Any] | None:
    with db._connection(init=_init_schema) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT data, expires FROM sessions WHERE kind = %s AND id = %s",
                (kind, key),
            )
            row = cursor.fetchone()

    if row is None or float(row[1]) < time.time():
        return None

    return db._as_dict(row[0])


def _db_delete(kind: str, key: str) -> None:
    with db._connection(init=_init_schema) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM sessions WHERE kind = %s AND id = %s",
                (kind, key),
            )


# ------------------------------------------------------------------ dispatch


def put(kind: str, key: str, payload: dict[str, Any]) -> None:
    if db.use_database():
        _db_put(kind, key, payload)
    else:
        with _LOCK:
            _file_put(kind, key, payload)
            _file_prune()


def pop(kind: str, key: str) -> dict[str, Any] | None:
    if db.use_database():
        return _db_pop(kind, key)

    return _file_pop(kind, key)


def get(kind: str, key: str) -> dict[str, Any] | None:
    if db.use_database():
        return _db_get(kind, key)

    return _file_get(kind, key)


def delete(kind: str, key: str) -> None:
    if db.use_database():
        _db_delete(kind, key)
    else:
        _file_delete(kind, key)


__all__ = [
    "PENDING_TTL_SECONDS",
    "SESSIONS_DIR",
    "delete",
    "get",
    "pop",
    "put",
]
