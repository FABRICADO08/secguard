import json
from datetime import UTC, datetime, timedelta

import pytest

from backend.config import settings
from backend.security import api_keys
from backend.security.auth import SCAN, request_is_authorized
from backend.storage import audit, portfolio_settings

REMOTE = {"REMOTE_ADDR": "203.0.113.9"}

MASTER = {"Authorization": "Bearer t0ken"}


@pytest.fixture
def master(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "t0ken")


def _create(client, scopes, days=90):
    response = client.post("/api/keys", json={"name": "ci", "scopes": scopes, "expires_in_days": days},
                           headers=MASTER, environ_base=REMOTE)
    assert response.status_code == 201
    return response.get_json()


def _authorized(token, scope="admin", environ=REMOTE):
    from backend.app import app

    with app.test_request_context("/", headers={"Authorization": f"Bearer {token}"}, environ_base=environ):
        return request_is_authorized(scope)


def test_a_new_key_is_shown_once_and_stored_hashed(client, master):
    body = _create(client, ["scan"])
    token = body["token"]

    assert token.startswith(f"sgk_{body['key']['id']}_") and "hash" not in body["key"]
    stored = json.dumps(portfolio_settings.load("api_keys"))
    assert token.split("_", 2)[2] not in stored
    listed = client.get("/api/keys", headers=MASTER, environ_base=REMOTE).get_json()["keys"]
    assert [key["id"] for key in listed] == [body["key"]["id"]] and listed[0]["active"]
    assert "hash" not in listed[0]


def test_scopes_limit_what_a_key_can_do(client, master):
    scan = _create(client, ["scan"])["token"]
    admin = _create(client, ["admin"])["token"]

    assert _authorized(scan, SCAN) and not _authorized(scan)
    assert _authorized(admin, SCAN) and _authorized(admin)
    assert client.get("/api/keys", headers={"Authorization": f"Bearer {scan}"}, environ_base=REMOTE).status_code == 403
    assert client.get("/api/keys", headers={"Authorization": f"Bearer {admin}"}, environ_base=REMOTE).status_code == 200


def test_a_scan_key_cannot_delete_applications(client, master):
    scan = _create(client, ["scan"])["token"]

    response = client.delete("/api/applications/missing", headers={"X-API-Key": scan}, environ_base=REMOTE)

    assert response.status_code == 401 and "'admin' scope" in response.get_json()["error"]


def test_expired_revoked_and_tampered_keys_are_refused(client, master):
    _, token = api_keys.create("old", ["admin"], 1, "test", now=datetime.now(UTC) - timedelta(days=2))
    assert not _authorized(token)

    live = _create(client, ["admin"])
    assert _authorized(live["token"])
    assert not _authorized(live["token"][:-2] + "zz")

    assert client.delete(f"/api/keys/{live['key']['id']}", headers=MASTER, environ_base=REMOTE).status_code == 200
    assert not _authorized(live["token"])
    assert client.delete("/api/keys/000000000000", headers=MASTER, environ_base=REMOTE).status_code == 404


def test_an_invalid_key_is_refused_even_from_loopback(client):
    assert not _authorized("sgk_000000000000_" + "a" * 43, environ={"REMOTE_ADDR": "127.0.0.1"})


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "", "scopes": ["scan"]},
        {"name": "ci", "scopes": []},
        {"name": "ci", "scopes": ["root"]},
        {"name": "ci", "scopes": ["scan"], "expires_in_days": 0},
        {"name": "ci", "scopes": ["scan"], "expires_in_days": 400},
        {"name": "ci", "scopes": ["scan"], "expires_in_days": True},
    ],
)
def test_invalid_requests_are_rejected(client, master, payload):
    assert client.post("/api/keys", json=payload, headers=MASTER, environ_base=REMOTE).status_code == 400


def test_key_management_needs_an_administrator(client, master):
    assert client.get("/api/keys", environ_base=REMOTE).status_code == 403
    assert client.post("/api/keys", json={"name": "x", "scopes": ["scan"]}, environ_base=REMOTE).status_code == 403


def test_the_audit_log_names_the_key(client, master):
    body = _create(client, ["admin"])

    client.delete("/api/applications/missing", headers={"X-API-Key": body["token"]}, environ_base=REMOTE)

    assert audit.recent(1)[0]["actor"] == f"api-key:{body['key']['id']}"
