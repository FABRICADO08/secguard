from datetime import UTC, datetime

from backend.config import settings
from backend.storage import retention, scans

NOW = datetime(2026, 10, 26, tzinfo=UTC)


def _scan(application_id, updated_at, repository="acme/api"):
    scans.save_application({"id": application_id, "name": application_id, "final_url": "", "requested_url": "",
                            "platform": "Repository", "created_at": updated_at, "updated_at": updated_at,
                            "repository": {"repository": {"name": repository}}})


def test_old_scans_go_but_each_system_keeps_its_newest():
    applications = [
        {"id": "old", "repository": "acme/api", "updated_at": "2026-01-01T00:00:00+00:00"},
        {"id": "recent", "repository": "acme/api", "updated_at": "2026-10-20T00:00:00+00:00"},
        {"id": "newest", "repository": "acme/api", "updated_at": "2026-10-25T00:00:00+00:00"},
        {"id": "only", "repository": "acme/web", "updated_at": "2025-01-01T00:00:00+00:00"},
        {"id": "undated", "repository": "acme/api"},
    ]

    assert retention.expired(applications, "2026-10-01T00:00:00+00:00") == ["old"]


def test_web_scans_are_grouped_by_url():
    applications = [
        {"id": "a", "url": "https://Example.test/", "updated_at": "2026-01-01T00:00:00+00:00"},
        {"id": "b", "url": "https://example.test/", "updated_at": "2026-02-01T00:00:00+00:00"},
    ]

    assert retention.expired(applications, "2026-10-01T00:00:00+00:00") == ["a"]


def test_prune_deletes_expired_scans(client):
    _scan("old", "2026-01-01T00:00:00+00:00")
    _scan("new", "2026-10-25T00:00:00+00:00")

    result = retention.prune(days=30, now=NOW)

    assert result["deleted"] == ["old"]
    assert not scans.application_exists("old") and scans.application_exists("new")


def test_dry_run_and_disabled_retention_delete_nothing(client, monkeypatch):
    _scan("old", "2026-01-01T00:00:00+00:00")
    _scan("new", "2026-10-25T00:00:00+00:00")
    monkeypatch.setattr(settings, "SCAN_RETENTION_DAYS", 0)

    assert retention.prune(now=NOW)["deleted"] == []
    assert retention.prune(days=30, dry_run=True, now=NOW)["deleted"] == ["old"]
    assert scans.application_exists("old")


def test_prune_endpoint_needs_credentials(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "t0ken")
    monkeypatch.setattr(settings, "SCAN_RETENTION_DAYS", 30)
    _scan("old", "2000-01-01T00:00:00+00:00")
    _scan("new", "2099-01-01T00:00:00+00:00")
    remote = {"REMOTE_ADDR": "203.0.113.9"}

    assert client.post("/api/retention/prune", environ_base=remote).status_code == 401

    response = client.post("/api/retention/prune?dry_run=1", headers={"Authorization": "Bearer t0ken"},
                           environ_base=remote)
    assert response.get_json()["deleted"] == ["old"] and scans.application_exists("old")


def test_cli_prints_the_result(client, capsys):
    _scan("old", "2000-01-01T00:00:00+00:00")
    _scan("new", "2099-01-01T00:00:00+00:00")

    assert retention.main(["--days", "30", "--dry-run"]) == 0
    assert '"old"' in capsys.readouterr().out
