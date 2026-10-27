import pytest

from backend.config import settings
from backend.storage import db


def _configure(monkeypatch, **values):
    defaults = {
        "GITHUB_CLIENT_ID": "id",
        "GITHUB_CLIENT_SECRET": "secret",
        "SECRET_KEY": "key",
        "SESSION_COOKIE_SECURE": True,
        "API_TOKEN": "token",
        "DATABASE_URL": "postgresql://db/secguard",
        "ALLOW_FILE_STORAGE": False,
        "ALLOW_PRIVATE_TARGETS": False,
        "PRODUCTION": True,
    }
    for name, value in {**defaults, **values}.items():
        monkeypatch.setattr(settings, name, value)


def test_a_complete_production_configuration_starts(monkeypatch):
    _configure(monkeypatch)

    assert settings.production_problems() == []
    settings.check_production()


def test_an_unsafe_production_configuration_refuses_to_start(monkeypatch):
    _configure(monkeypatch, GITHUB_CLIENT_SECRET="", SECRET_KEY="", API_TOKEN="", DATABASE_URL="",
               ALLOW_PRIVATE_TARGETS=True)

    with pytest.raises(RuntimeError) as failure:
        settings.check_production()

    message = str(failure.value)
    for name in ("SECGUARD_GITHUB_CLIENT_SECRET", "SECGUARD_SECRET_KEY", "SECGUARD_API_TOKEN",
                 "POSTGRES_URL", "SECGUARD_ALLOW_PRIVATE_TARGETS"):
        assert name in message
    assert "SECGUARD_SECURE_COOKIES" not in message


def test_file_storage_can_be_chosen_explicitly(monkeypatch):
    _configure(monkeypatch, DATABASE_URL="", ALLOW_FILE_STORAGE=True)

    assert settings.production_problems() == []


def test_the_check_is_off_outside_production(monkeypatch):
    _configure(monkeypatch, PRODUCTION=False, API_TOKEN="")

    settings.check_production()


def test_ready_with_file_storage(client):
    response = client.get("/api/health/ready")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ready", "checks": {"storage": "ok"}}


def test_an_unwritable_session_store_is_not_ready(client, monkeypatch, tmp_path):
    from backend.storage import sessions

    blocked = tmp_path / "file"
    blocked.write_text("")
    monkeypatch.setattr(sessions, "SESSIONS_DIR", blocked / "sessions")

    assert client.get("/api/health/ready").status_code == 503


def test_an_unreachable_database_is_not_ready(client, monkeypatch, caplog):
    def refuse():
        raise OSError("connection refused to db.internal:5432 password=hunter2")

    monkeypatch.setattr(db, "use_database", lambda: True)
    monkeypatch.setattr(db, "ping", refuse)

    response = client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.get_json()["checks"] == {"storage": "unavailable"}
    assert "hunter2" not in response.get_data(as_text=True)
    assert "hunter2" not in caplog.text and "OSError" in caplog.text


def test_ping_runs_a_query(monkeypatch):
    executed = []

    class Cursor:
        def execute(self, sql):
            executed.append(sql)

        def fetchone(self):
            return (1,)

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        def close(self):
            Connection.closed = True

    monkeypatch.setattr(db, "_connector", Connection)

    db.ping()

    assert executed == ["SELECT 1"] and Connection.closed
