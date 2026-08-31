import io
import json
from pathlib import Path

import pytest

from backend import app as app_module
from backend.storage import findings as findings_storage
from backend.storage import scans

MODEL_FILE = (
    Path(__file__).resolve().parent / "fixtures" / "mendix_model.json"
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
        "/api/mendix/analyze",
        json={"model": document, "name": "sales.json"},
    )


def test_json_body_model_is_analyzed(client, model_document):
    response = analyze(client, model_document)

    payload = response.get_json()
    application = payload["application"]
    security = application["security"]

    assert response.status_code == 200
    assert application["platform"] == "Mendix"
    assert application["name"] == "sales.json"
    assert application["status"] == "analyzed"
    assert payload["model_statistics"]["entities"] == 2
    assert security["total_findings"] == len(security["findings"])
    assert security["risk_score"] > 0
    assert security["recommendations"]


def test_findings_are_normalized(client, model_document):
    findings = (
        analyze(client, model_document)
        .get_json()["application"]["security"]["findings"]
    )

    rule_ids = {finding["rule_id"] for finding in findings}

    assert {"MXSEC-101", "MXSEC-102"} <= rule_ids

    for finding in findings:
        assert finding["id"]
        assert finding["detected_at"]
        assert finding["platform"] == "Mendix"
        assert finding["category"]
        assert finding["confidence"]
        assert finding["recommendation"]
        assert finding["risk"]["score"] > 0

    scores = [finding["risk"]["score"] for finding in findings]

    assert scores == sorted(scores, reverse=True)


def test_findings_are_persisted_and_served(client, model_document):
    application_id = (
        analyze(client, model_document).get_json()["application_id"]
    )

    stored = findings_storage.load_findings(application_id)

    response = client.get(
        f"/api/applications/{application_id}/findings",
        query_string={"platform": "Mendix"},
    )

    assert stored
    assert response.status_code == 200
    assert len(response.get_json()["findings"]) == len(stored)


def test_multipart_upload_is_analyzed(client):
    response = client.post(
        "/api/mendix/analyze",
        data={
            "model": (
                io.BytesIO(MODEL_FILE.read_bytes()),
                "domain-model.json",
            )
        },
        content_type="multipart/form-data",
    )

    payload = response.get_json()

    assert response.status_code == 200
    assert payload["application"]["name"] == "domain-model.json"
    assert payload["application"]["security"]["findings"]


def test_empty_upload_is_rejected(client):
    response = client.post(
        "/api/mendix/analyze",
        data={"model": (io.BytesIO(b"   "), "domain-model.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "empty" in response.get_json()["error"].lower()


def test_invalid_json_upload_is_rejected(client):
    response = client.post(
        "/api/mendix/analyze",
        data={"model": (io.BytesIO(b"{not json"), "domain-model.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "valid JSON" in response.get_json()["error"]


def test_oversized_upload_is_rejected(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_MODEL_BYTES", 8)

    response = client.post(
        "/api/mendix/analyze",
        data={"model": (io.BytesIO(b"{}" * 32), "domain-model.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "upload limit" in response.get_json()["error"]


def test_non_object_model_is_rejected(client):
    response = client.post(
        "/api/mendix/analyze",
        json={"model": ["not", "an", "object"]},
    )

    assert response.status_code == 400
    assert "object" in response.get_json()["error"]


def test_missing_body_is_rejected(client):
    response = client.post("/api/mendix/analyze")

    assert response.status_code == 400
    assert "model" in response.get_json()["error"]


ACCESS_MODEL_FILE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "mendix_model_access.json"
)


@pytest.fixture
def access_model_document():
    return json.loads(ACCESS_MODEL_FILE.read_text(encoding="utf-8"))


def rule_ids(payload):
    return {
        finding["rule_id"]
        for finding in payload["application"]["security"]["findings"]
    }


def test_upload_filename_is_stripped_of_markup(client, model_document):
    response = client.post(
        "/api/mendix/analyze",
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


def test_json_name_is_stripped_of_markup(client, model_document):
    response = client.post(
        "/api/mendix/analyze",
        json={
            "model": model_document,
            "name": "<script>alert(1)</script>",
        },
    )

    name = response.get_json()["application"]["name"]

    assert response.status_code == 200
    assert "<" not in name
    assert ">" not in name


def test_oversized_json_body_is_rejected(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_MODEL_BYTES", 8)

    response = client.post(
        "/api/mendix/analyze",
        json={"model": {"units": [{"$Type": "Projects$Module"}] * 64}},
    )

    assert response.status_code == 400
    assert "upload limit" in response.get_json()["error"]


def test_empty_object_model_is_rejected(client):
    response = client.post("/api/mendix/analyze", json={"model": {}})

    assert response.status_code == 400
    assert "Mendix model elements" in response.get_json()["error"]


def test_unrelated_json_document_is_rejected(client):
    response = client.post(
        "/api/mendix/analyze",
        json={"model": {"hello": "world", "items": [1, 2, 3]}},
    )

    assert response.status_code == 400
    assert "Mendix model elements" in response.get_json()["error"]


def test_delete_only_access_rule_is_reported(
    client,
    access_model_document,
):
    response = analyze(client, access_model_document)

    assert response.status_code == 200
    assert "MXSEC-101" in rule_ids(response.get_json())


def test_member_access_to_sensitive_attribute_is_reported(
    client,
    access_model_document,
):
    response = analyze(client, access_model_document)

    assert response.status_code == 200
    assert "MXSEC-106" in rule_ids(response.get_json())


def test_cascading_association_delete_is_reported(client, model_document):
    response = analyze(client, model_document)

    assert response.status_code == 200
    assert "MXSEC-401" in rule_ids(response.get_json())


def test_rule_errors_is_a_list(client, model_document):
    response = analyze(client, model_document)

    security = response.get_json()["application"]["security"]

    assert security["rule_errors"] == []
