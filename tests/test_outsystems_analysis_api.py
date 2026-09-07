import io
import json
from pathlib import Path

import pytest

from backend import app as app_module
from backend.config import settings
from backend.storage import findings as findings_storage
from backend.storage import scans

MODEL_FILE = (
    Path(__file__).resolve().parent / "fixtures" / "outsystems_model.json"
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")

    app_module.app.config.update(TESTING=True)

    return app_module.app.test_client()


@pytest.fixture
def model_document():
    return json.loads(MODEL_FILE.read_text(encoding="utf-8"))


def analyze(client, document):
    return client.post(
        "/api/outsystems/analyze",
        json={"model": document, "name": "portal.json"},
    )


def findings_of(response):
    return response.get_json()["application"]["security"]["findings"]


def rule_ids(response):
    return {finding["rule_id"] for finding in findings_of(response)}


def locations(response, rule_id):
    return {
        finding["location"]
        for finding in findings_of(response)
        if finding["rule_id"] == rule_id
    }


def test_json_body_model_is_analyzed(client, model_document):
    response = analyze(client, model_document)

    payload = response.get_json()
    application = payload["application"]
    security = application["security"]

    assert response.status_code == 200
    assert application["platform"] == "OutSystems"
    assert application["name"] == "portal.json"
    assert application["status"] == "analyzed"
    assert payload["model_statistics"]["entities"] == 2
    assert payload["model_statistics"]["rest_methods"] == 2
    assert security["total_findings"] == len(security["findings"])
    assert security["risk_score"] > 0
    assert security["recommendations"]


def test_findings_are_normalized(client, model_document):
    findings = findings_of(analyze(client, model_document))

    for finding in findings:
        assert finding["id"]
        assert finding["detected_at"]
        assert finding["platform"] == "OutSystems"
        assert finding["category"]
        assert finding["confidence"]
        assert finding["recommendation"]
        assert finding["risk"]["score"] > 0

    scores = [finding["risk"]["score"] for finding in findings]

    assert scores == sorted(scores, reverse=True)


def test_unprotected_screen_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-101") == {
        "CustomerPortal.Login",
        "CustomerPortal.AgentConsole",
    }


def test_unauthenticated_rest_method_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-102") == {
        "CustomerPortal.CustomerApi.ListCustomers",
    }


def test_public_writable_entity_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-103") == {"CustomerPortal.Customer"}


def test_secret_site_property_default_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-104") == {
        "CustomerPortal.BillingApiKey",
    }


def test_secret_value_is_not_stored_in_the_model(client, model_document):
    payload = analyze(client, model_document).get_json()

    stored = json.dumps(payload["application"]["model"])

    assert "sk-example-not-a-real-key" not in stored


def test_unencrypted_sensitive_attributes_are_reported(
    client,
    model_document,
):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-105") == {
        "CustomerPortal.Customer.Email",
        "CustomerPortal.Customer.ApiKey",
    }


def test_inline_sql_parameter_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-106") == {
        "CustomerPortal.SearchCustomers",
    }


def test_plain_http_consumed_api_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert locations(response, "OSSEC-107") == {"CustomerPortal.BillingApi"}


def test_findings_are_persisted_and_served(client, model_document):
    application_id = (
        analyze(client, model_document).get_json()["application_id"]
    )

    stored = findings_storage.load_findings(application_id)

    response = client.get(
        f"/api/applications/{application_id}/findings",
        query_string={"platform": "OutSystems"},
    )

    assert stored
    assert response.status_code == 200
    assert len(response.get_json()["findings"]) == len(stored)


def test_multipart_upload_is_analyzed(client):
    response = client.post(
        "/api/outsystems/analyze",
        data={
            "model": (
                io.BytesIO(MODEL_FILE.read_bytes()),
                "portal-export.json",
            )
        },
        content_type="multipart/form-data",
    )

    payload = response.get_json()

    assert response.status_code == 200
    assert payload["application"]["name"] == "portal-export.json"
    assert payload["application"]["security"]["findings"]


def test_upload_filename_is_stripped_of_markup(client, model_document):
    response = client.post(
        "/api/outsystems/analyze",
        data={
            "model": (
                io.BytesIO(json.dumps(model_document).encode("utf-8")),
                "../<img src=x onerror=alert(1)>.json",
            )
        },
        content_type="multipart/form-data",
    )

    name = response.get_json()["application"]["name"]

    assert response.status_code == 200
    assert "<" not in name
    assert ">" not in name
    assert "/" not in name


def test_invalid_json_upload_is_rejected(client):
    response = client.post(
        "/api/outsystems/analyze",
        data={"model": (io.BytesIO(b"{not json"), "portal.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "valid JSON" in response.get_json()["error"]


def test_oversized_upload_is_rejected(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_MODEL_BYTES", 8)

    response = client.post(
        "/api/outsystems/analyze",
        data={"model": (io.BytesIO(b"{}" * 32), "portal.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "upload limit" in response.get_json()["error"]


def test_empty_object_model_is_rejected(client):
    response = client.post("/api/outsystems/analyze", json={"model": {}})

    assert response.status_code == 400
    assert "OutSystems model elements" in response.get_json()["error"]


def test_unrelated_json_document_is_rejected(client):
    response = client.post(
        "/api/outsystems/analyze",
        json={"model": {"hello": "world", "items": [1, 2, 3]}},
    )

    assert response.status_code == 400
    assert "OutSystems model elements" in response.get_json()["error"]


def test_non_object_model_is_rejected(client):
    response = client.post(
        "/api/outsystems/analyze",
        json={"model": ["not", "an", "object"]},
    )

    assert response.status_code == 400
    assert "object" in response.get_json()["error"]


def test_missing_body_is_rejected(client):
    response = client.post("/api/outsystems/analyze")

    assert response.status_code == 400
    assert "model" in response.get_json()["error"]


def test_endpoint_requires_the_configured_token(
    client,
    model_document,
    monkeypatch,
):
    monkeypatch.setattr(settings, "API_TOKEN", "secret-token")

    unauthenticated = analyze(client, model_document)

    authenticated = client.post(
        "/api/outsystems/analyze",
        json={"model": model_document},
        headers={"X-API-Key": "secret-token"},
    )

    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200
