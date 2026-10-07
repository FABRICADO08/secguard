"""The Postgres storage path, exercised through a fake psycopg connection.

No database server is needed: the fake executes the handful of statements
``backend.storage.db`` issues against in-memory dicts, so the dispatch and
the row mapping are tested the same way a real Neon database is driven.
"""

from __future__ import annotations

import json

import pytest

from backend.storage import application_names
from backend.storage import db
from backend.storage import findings as findings_storage
from backend.storage import scans


def _upsert(table):
    return lambda tables, params: tables[table].__setitem__(params[0], params[1])


def _select_row(table):
    def run(tables, params):
        if params[0] in tables[table]:
            return [(tables[table][params[0]],)]

        return []

    return run


def _select_exists(table):
    return lambda tables, params: [(1,)] if params[0] in tables[table] else []


def _select_all(table):
    return lambda tables, params: [(row,) for row in tables[table].values()]


def _delete(table):
    def run(tables, params):
        removed = tables[table].pop(params[0], None) is not None

        return [], 1 if removed else 0

    return run


def _select_pairs(table):
    return lambda tables, params: list(tables[table].items())


# Each entry maps the normalized statement prefix to a handler returning the
# result rows, or (rows, rowcount) when a count matters.
HANDLERS = {
    "CREATE TABLE": lambda tables, params: [],
    "INSERT INTO applications": _upsert("applications"),
    "SELECT data FROM applications WHERE id": _select_row("applications"),
    "SELECT 1 FROM applications WHERE id": _select_exists("applications"),
    "SELECT data FROM applications": _select_all("applications"),
    "DELETE FROM applications": _delete("applications"),
    "INSERT INTO findings": _upsert("findings"),
    "SELECT data FROM findings WHERE application_id": _select_row("findings"),
    "DELETE FROM findings": _delete("findings"),
    "INSERT INTO application_names": _upsert("names"),
    "SELECT repository, name FROM application_names": _select_pairs("names"),
}


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 0
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params=()):
        normalized = " ".join(query.split())

        handler = next(
            (
                handler
                for prefix, handler in HANDLERS.items()
                if normalized.startswith(prefix)
            ),
            None,
        )

        if handler is None:
            raise AssertionError(f"Unexpected SQL: {normalized}")

        outcome = handler(self.connection.tables, params)

        self._result, self.rowcount = (
            outcome if isinstance(outcome, tuple) else (outcome, 0)
        )

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)


class FakeConnection:
    def __init__(self):
        self.tables = {"applications": {}, "findings": {}, "names": {}}
        self.commits = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def close(self):
        pass


@pytest.fixture
def fake_db(monkeypatch):
    connections = []

    def connect():
        connection = FakeConnection()
        connections.append(connection)
        return connection

    # Every operation opens a fresh connection but shares the tables, like
    # separate connections against one database.
    shared = FakeConnection()

    def shared_connect():
        connection = FakeConnection()
        connection.tables = shared.tables
        connections.append(connection)
        return connection

    monkeypatch.setattr(db, "_override", True)
    monkeypatch.setattr(db, "_connector", shared_connect)
    monkeypatch.setattr(db, "_ready", False)

    yield shared

    db.reset()


def test_use_database_falls_back_to_settings(monkeypatch):
    db.reset()

    monkeypatch.setattr(db.settings, "DATABASE_URL", "")
    assert db.use_database() is False

    monkeypatch.setattr(db.settings, "DATABASE_URL", "postgresql://db")
    assert db.use_database() is True

    db.reset()


def test_application_round_trip(fake_db):
    application = {
        "id": "app-1",
        "name": "Test app",
        "final_url": "https://app.test/",
        "requested_url": "https://app.test",
        "platform": "Generic",
        "status": "analyzed",
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-02T00:00:00",
        "security": {
            "risk_score": 70,
            "risk_grade": "D",
            "total_findings": 2,
            "severity_counts": {"medium": 2},
        },
    }

    assert scans.application_exists("app-1") is False

    scans.save_application(application)

    assert scans.application_exists("app-1") is True
    assert scans.load_application("app-1") == application

    # Saving again updates rather than duplicating.
    application["name"] = "Renamed"
    scans.save_application(application)

    assert scans.load_application("app-1")["name"] == "Renamed"
    assert len(scans.list_applications()) == 1


def test_load_missing_application_raises(fake_db):
    with pytest.raises(FileNotFoundError):
        scans.load_application("missing")


def test_list_applications_maps_summary_fields(fake_db):
    scans.save_application(
        {
            "id": "app-1",
            "name": "One",
            "updated_at": "2026-01-01",
            "security": {"risk_score": 10, "findings": [{"id": "f1"}]},
            "repository": {"repository": {"name": "octo/demo"}, "health": {"grade": "A"}},
        }
    )
    scans.save_application(
        {
            "id": "app-2",
            "name": "Two",
            "updated_at": "2026-01-03",
        }
    )

    summaries = scans.list_applications()

    assert [item["id"] for item in summaries] == ["app-2", "app-1"]

    first = next(item for item in summaries if item["id"] == "app-1")

    assert first["repository"] == "octo/demo"
    assert first["health"] == {"grade": "A"}
    assert first["total_findings"] == 1
    assert first["platform"] == "Unknown"

    # A corrupt row is skipped, mirroring the file store's behaviour.
    fake_db.tables["applications"]["broken"] = "not json"

    assert len(scans.list_applications()) == 2


def test_delete_application_removes_findings_too(fake_db):
    scans.save_application({"id": "app-1", "name": "One"})
    findings_storage.save_findings("app-1", [{"id": "f1"}])

    assert scans.delete_application("app-1") is True
    assert scans.application_exists("app-1") is False
    assert findings_storage.load_findings("app-1") == []
    assert scans.delete_application("app-1") is False


def test_delete_rejects_path_like_ids(fake_db):
    assert scans.delete_application("../outsider") is False
    assert scans.delete_application("") is False


def test_findings_round_trip(fake_db):
    assert findings_storage.load_findings("app-1") == []

    findings_storage.save_findings("app-1", [{"id": "f1", "severity": "high"}])

    assert findings_storage.load_findings("app-1") == [
        {"id": "f1", "severity": "high"}
    ]

    findings_storage.save_findings("app-1", [])

    assert findings_storage.load_findings("app-1") == []


def test_application_names_round_trip(fake_db):
    assert application_names.name_for("Octo/Demo") == ""

    application_names.set_name("Octo/Demo", "Customer Portal")

    # Lookups are case-insensitive; the stored key is lower-cased.
    assert application_names.name_for("octo/demo") == "Customer Portal"

    application_names.set_name("octo/demo", "Portal")

    assert application_names.name_for("OCTO/DEMO") == "Portal"


def test_payloads_keep_unicode_and_nesting(fake_db):
    application = {
        "id": "app-u",
        "name": "Sécurity — ünïcode",
        "security": {"findings": [{"title": "émoji ✅", "nested": {"a": [1, 2]}}]},
    }

    scans.save_application(application)

    stored = scans.load_application("app-u")

    assert stored == application
    # pg8000 serializes dict parameters to JSONB itself.
    assert fake_db.tables["applications"]["app-u"] == application

    # A driver that hands JSONB back as text is still understood.
    fake_db.tables["applications"]["app-u"] = json.dumps(application)

    assert scans.load_application("app-u") == application
