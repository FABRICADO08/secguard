from datetime import date, datetime, timezone

import pytest

from backend import app as app_module
from backend.portfolio import triage
from backend.storage import scans


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def _store(application_id, detected="2026-01-01T00:00:00+00:00"):
    scans.save_application(
        {
            "id": application_id,
            "name": "Customer Portal",
            "requested_url": "https://portal.test",
            "platform": "Unknown",
            "status": "analyzed",
        }
    )
    scans.save_json(
        scans.application_directory(application_id) / "findings.json",
        {
            "application_id": application_id,
            "findings": [
                {
                    "id": f"{application_id}-f1",
                    "rule_id": "GEN-TLS-001",
                    "severity": "high",
                    "title": "Weak TLS",
                    "location": "https://portal.test",
                    "detected_at": detected,
                }
            ],
        },
    )


def _url(application_id):
    return f"/api/applications/{application_id}/findings/{application_id}-f1/workflow"


def test_new_findings_are_open_with_a_due_date_from_their_severity(client):
    _store("scan-1")

    (finding,) = client.get("/api/applications/scan-1/findings").get_json()["findings"]

    assert finding["workflow"]["status"] == "open"
    assert finding["workflow"]["due_date"] == "2026-01-31"
    assert finding["workflow"]["overdue"] is True


def test_decision_is_audited_and_carries_over_to_the_next_scan(client):
    _store("scan-1")

    response = client.put(
        _url("scan-1"),
        json={"status": "accepted_risk", "reason": "Internal only", "owner": "alice"},
    )

    assert response.status_code == 200
    workflow = response.get_json()["workflow"]
    assert (workflow["status"], workflow["overdue"]) == ("accepted_risk", False)
    (entry,) = workflow["history"]
    assert entry["by"] == "administrator"
    assert entry["changes"]["status"] == {"from": "open", "to": "accepted_risk"}

    _store("scan-2", detected="2026-02-01T00:00:00+00:00")
    findings = client.get("/api/applications/scan-2/findings?status=accepted_risk").get_json()["findings"]
    assert findings[0]["workflow"]["owner"] == "alice"
    assert client.get("/api/applications/scan-2/findings?status=open").get_json()["findings"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "false_positive"},
        {"status": "closed"},
        {"due_date": "next week"},
        {"owner": "x" * 101},
        {"owner": 3},
        ["status"],
    ],
)
def test_invalid_changes_are_refused(client, payload):
    _store("scan-1")

    response = client.put(_url("scan-1"), json=payload)

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_remote_callers_without_the_api_token_cannot_change_the_workflow(client):
    _store("scan-1")

    response = client.put(
        _url("scan-1"), json={"status": "in_progress"}, environ_base={"REMOTE_ADDR": "203.0.113.9"}
    )

    assert response.status_code == 403


def test_github_users_need_push_access_to_triage_repository_findings(client, monkeypatch):
    user = type("User", (), {"login": "bob", "repositories": {"octo/demo": {"can_trigger": False}}})()
    monkeypatch.setattr(app_module.github_auth, "enabled", lambda: True)
    monkeypatch.setattr(app_module.github_auth, "current_user", lambda: user)
    monkeypatch.setattr(app_module.github_auth, "can_view", lambda application: True)
    _store("scan-1")
    record = scans.load_application("scan-1")
    record.update(platform="Repository", repository="octo/demo")
    scans.save_application(record)

    remote = {"REMOTE_ADDR": "203.0.113.9"}
    assert client.put(_url("scan-1"), json={"status": "in_progress"}, environ_base=remote).status_code == 403

    user.repositories["octo/demo"]["can_trigger"] = True
    response = client.put(_url("scan-1"), json={"status": "in_progress"}, environ_base=remote)
    assert response.get_json()["workflow"]["history"][0]["by"] == "bob"


def test_signed_in_users_need_the_api_token_for_non_repository_findings(client, monkeypatch):
    user = type("User", (), {"login": "bob", "repositories": {}})()
    monkeypatch.setattr(app_module.github_auth, "enabled", lambda: True)
    monkeypatch.setattr(app_module.github_auth, "current_user", lambda: user)
    monkeypatch.setattr(app_module.github_auth, "can_view", lambda application: True)
    _store("scan-1")

    response = client.put(
        _url("scan-1"), json={"status": "in_progress"}, environ_base={"REMOTE_ADDR": "203.0.113.9"}
    )

    assert response.status_code == 403


def test_repository_decisions_follow_the_repository_not_the_display_name():
    first = {"platform": "Repository", "repository": "Octo/Demo", "name": "Portal"}
    renamed = {"platform": "Repository", "repository": "octo/demo", "name": "Customer Portal"}

    assert triage.system_key(first) == triage.system_key(renamed) == "github:octo/demo"


def test_unchanged_values_add_no_audit_entry():
    update, problem = triage.clean_update({"owner": ""}, {})
    record = triage.apply_update({}, update, "alice", datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert problem == ""
    assert record["history"] == []
    assert triage.workflow({"severity": "info"}, record, date(2026, 1, 1))["due_date"] == ""
