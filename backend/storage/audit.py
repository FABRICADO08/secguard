"""Append-only record of state-changing requests.

Postgres keeps it in ``audit_log``, where a trigger refuses UPDATE and
DELETE; without a database each entry is appended to a JSON-lines file.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from backend.storage import db, scans

AUDIT_FILE = scans.ROOT / "data" / "audit" / "audit.jsonl"

FIELDS = ("at", "actor", "method", "path", "status", "address")

_LOCK = threading.Lock()


def _init_schema(connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                at DOUBLE PRECISION NOT NULL,
                actor TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                address TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_log is append-only';
            END
            $$ LANGUAGE plpgsql
            """
        )
        cursor.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_log_append_only') THEN
                    CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
                    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
                END IF;
            END
            $$
            """
        )


def record(entry: dict[str, Any]) -> None:
    values = tuple(entry[name] for name in FIELDS)

    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_log (at, actor, method, path, status, address) VALUES (%s, %s, %s, %s, %s, %s)",
                values,
            )
        return

    line = json.dumps(dict(zip(FIELDS, values, strict=True)), sort_keys=True)
    with _LOCK:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _file_entries() -> list[dict[str, Any]]:
    if not AUDIT_FILE.exists():
        return []

    entries = []
    for line in AUDIT_FILE.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and all(name in entry for name in FIELDS):
            entries.append(entry)
    return entries


def recent(limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` entries, newest first."""
    if db.use_database():
        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT at, actor, method, path, status, address FROM audit_log ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            rows = cursor.fetchall()
        return [dict(zip(FIELDS, row, strict=True)) for row in rows]

    return list(reversed(_file_entries()[-limit:]))
