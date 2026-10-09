"""Postgres-backed storage, selected when ``DATABASE_URL`` is configured.

The rest of the application keeps calling the same functions in
``backend.storage.scans``, ``backend.storage.findings`` and
``backend.storage.application_names``; those modules dispatch here when a
connection string is present and fall back to the JSON-file store otherwise.

Rows are stored as JSONB so the document shape stays identical to the
file-based store and no per-field migration is needed when the payload grows.

The driver is pg8000 (pure Python, BSD-licensed), which takes connection
parameters rather than a URL, so the configured URL is parsed here. Neon
connection strings carry ``sslmode=require``; that maps to a default TLS
context.
"""

from __future__ import annotations

import json
import ssl
import threading
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from backend.config import settings

_lock = threading.Lock()

# Schemas (setup functions) already created in this process.
_ready: set = set()

# Tests override selection/connection through these two hooks.
_override = None

_connector = None


def use_database() -> bool:
    if _override is not None:
        return _override

    return bool(settings.DATABASE_URL)


def _connection_kwargs(url: str) -> dict[str, Any]:
    parts = urlsplit(url)

    query = dict(parse_qsl(parts.query))

    kwargs: dict[str, Any] = {
        "user": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "host": parts.hostname or "localhost",
        "port": parts.port or 5432,
        "database": parts.path.lstrip("/") or None,
    }

    sslmode = query.get("sslmode", "")

    if sslmode and sslmode != "disable":
        kwargs["ssl_context"] = ssl.create_default_context()

    return kwargs


def _connect():
    if _connector is not None:
        return _connector()

    import pg8000

    return pg8000.connect(**_connection_kwargs(settings.DATABASE_URL))


def _schema_ready(schema) -> bool:
    """The schema is created once per process per table group."""

    with _lock:
        if schema in _ready:
            return False

        _ready.add(schema)

    return True


@contextmanager
def _connection(init=None):
    """Open a connection, first running the caller's schema setup once.

    ``init`` defaults to the core schema; modules with their own tables
    pass a setup function so their schema exists without forcing the core
    one. A failed setup clears the process flag so the next call retries.
    """

    setup = init or init_schema

    if _schema_ready(setup):
        connection = _connect()
    else:
        connection = _connect()

        try:
            setup(connection)
            connection.commit()
        except BaseException:
            with _lock:
                _ready.discard(setup)

            connection.close()
            raise

    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_schema(connection=None) -> None:
    """Create the core tables; safe to call on every request.

    Takes an open connection when called from ``_connection``; called
    directly (as tests do) it opens and closes its own.
    """

    if connection is None:
        if not _schema_ready(init_schema):
            return

        owned = _connect()

        try:
            init_schema(owned)
            owned.commit()
        except BaseException:
            with _lock:
                _ready.discard(init_schema)

            raise
        finally:
            owned.close()

        return

    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                data JSONB NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                application_id TEXT PRIMARY KEY,
                data JSONB NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS application_names (
                repository TEXT PRIMARY KEY,
                name TEXT NOT NULL
            )
            """
        )


def reset() -> None:
    """Drop the cached schema flags and test hooks (used by tests)."""

    global _override, _connector

    _ready.clear()
    _override = None
    _connector = None


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return json.loads(value)


# ------------------------------------------------------------- applications


def save_application(application: dict[str, Any]) -> None:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO applications (id, data)
                VALUES (%s, %s)
                ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data
                """,
                (application["id"], application),
            )


def load_application(application_id: str) -> dict[str, Any]:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM applications WHERE id = %s",
                (application_id,),
            )
            row = cursor.fetchone()

    if row is None:
        raise FileNotFoundError(
            f"Stored application does not exist: {application_id}"
        )

    return _as_dict(row[0])


def application_exists(application_id: str) -> bool:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM applications WHERE id = %s",
                (application_id,),
            )
            row = cursor.fetchone()

    return row is not None


def delete_application(application_id: str) -> bool:
    if not application_id or "/" in application_id or "\\" in application_id:
        return False

    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM findings WHERE application_id = %s",
                (application_id,),
            )
            cursor.execute(
                "DELETE FROM applications WHERE id = %s",
                (application_id,),
            )
            return cursor.rowcount > 0


def application_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Build the public portfolio summary for one stored application."""
    security = data.get("security") or {}
    repository = data.get("repository") or {}

    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "url": data.get("final_url"),
        "requested_url": data.get("requested_url"),
        "platform": data.get("platform", "Unknown"),
        "status": data.get("status", "unknown"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "risk_score": security.get("risk_score", 0),
        "risk_grade": security.get("risk_grade", ""),
        "total_findings": security.get(
            "total_findings",
            len(security.get("findings", [])),
        ),
        "severity_counts": security.get("severity_counts", {}),
        "repository": (repository.get("repository") or {}).get("name", ""),
        "health": repository.get("health") or {},
    }


def list_applications() -> list[dict[str, Any]]:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT data FROM applications")
            rows = cursor.fetchall()

    applications = []

    for (raw,) in rows:
        try:
            data = _as_dict(raw)
        except (ValueError, TypeError):
            continue

        applications.append(application_summary(data))

    applications.sort(
        key=lambda item: item.get("updated_at") or "",
        reverse=True,
    )

    return applications


# ----------------------------------------------------------------- findings


def save_findings(application_id: str, findings: list[dict[str, Any]]) -> None:
    payload = {"application_id": application_id, "findings": findings}

    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO findings (application_id, data)
                VALUES (%s, %s)
                ON CONFLICT (application_id) DO UPDATE SET data = EXCLUDED.data
                """,
                (application_id, payload),
            )


def load_findings(application_id: str) -> list[dict[str, Any]]:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM findings WHERE application_id = %s",
                (application_id,),
            )
            row = cursor.fetchone()

    if row is None:
        return []

    return _as_dict(row[0]).get("findings", [])


# ---------------------------------------------------------- application names


def all_names() -> dict[str, str]:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT repository, name FROM application_names")
            rows = cursor.fetchall()

    return {str(repository): str(name) for repository, name in rows}


def set_name(repository: str, name: str) -> None:
    with _connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO application_names (repository, name)
                VALUES (%s, %s)
                ON CONFLICT (repository) DO UPDATE SET name = EXCLUDED.name
                """,
                (repository.lower(), name),
            )
