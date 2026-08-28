import pytest

from backend import app as app_module
from backend.storage import scans


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")

    app_module.app.config.update(TESTING=True)

    return app_module.app.test_client()


@pytest.fixture
def stored_application(client):
    application = {
        "id": "app-1",
        "name": "Test app",
        "requested_url": "https://app.test",
        "final_url": "https://app.test/",
        "platform": "Unknown",
        "status": "analyzed",
        "security": {
            "risk_score": 70,
            "risk_grade": "D",
            "total_findings": 2,
        },
    }

    scans.save_application(application)

    scans.save_json(
        scans.application_directory("app-1") / "findings.json",
        {
            "application_id": "app-1",
            "findings": [
                {
                    "id": "finding-1",
                    "rule_id": "GEN-HDR-001",
                    "severity": "medium",
                    "category": "configuration",
                    "platform": "Generic",
                    "title": "CSP missing",
                },
                {
                    "id": "finding-2",
                    "rule_id": "GEN-TLS-001",
                    "severity": "high",
                    "category": "transport",
                    "platform": "Generic",
                    "title": "Plain HTTP",
                },
            ],
        },
    )

    return application


def test_health(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_rules_catalogue_is_populated(client):
    payload = client.get("/api/rules").get_json()

    assert payload["success"] is True
    assert len(payload["rules"]) >= 20
    assert all(rule["id"] for rule in payload["rules"])


def test_rule_ids_are_unique(client):
    ids = [rule["id"] for rule in client.get("/api/rules").get_json()["rules"]]

    assert len(ids) == len(set(ids))


def test_discover_requires_a_url(client):
    response = client.post("/api/discover", json={})

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_findings_are_returned_with_a_summary(client, stored_application):
    payload = client.get("/api/applications/app-1/findings").get_json()

    assert payload["success"] is True
    assert len(payload["findings"]) == 2
    assert payload["summary"]["highest_severity"] == "high"


def test_findings_can_be_filtered(client, stored_application):
    payload = client.get(
        "/api/applications/app-1/findings?severity=high"
    ).get_json()

    assert [finding["id"] for finding in payload["findings"]] == ["finding-2"]
    assert payload["filters"] == {"severity": "high"}


def test_single_finding_is_returned(client, stored_application):
    payload = client.get(
        "/api/applications/app-1/findings/finding-1"
    ).get_json()

    assert payload["finding"]["rule_id"] == "GEN-HDR-001"


def test_unknown_finding_returns_404(client, stored_application):
    response = client.get("/api/applications/app-1/findings/nope")

    assert response.status_code == 404


def test_findings_for_unknown_application_return_404(client):
    response = client.get("/api/applications/missing/findings")

    assert response.status_code == 404


def test_application_list_includes_risk(client, stored_application):
    applications = client.get("/api/applications").get_json()["applications"]

    assert applications[0]["risk_score"] == 70
    assert applications[0]["risk_grade"] == "D"
