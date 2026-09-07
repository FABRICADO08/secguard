import socket
import time

import pytest
import requests

from backend import app as app_module
from backend.config import settings
from backend.discovery import crawler
from backend.discovery.http import build_session
from backend.security.rate_limit import RateLimiter
from backend.security.targets import (
    BlockedTargetError,
    assert_target_allowed,
    guard_response,
    unwrap_blocked,
)
from backend.storage import scans

REMOTE = {"REMOTE_ADDR": "203.0.113.10"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")

    app_module.app.config.update(TESTING=True)

    return app_module.app.test_client()


@pytest.fixture
def listening_port():
    """A loopback listener the guarded session must refuse to talk to."""

    server = socket.socket()

    server.bind(("127.0.0.1", 0))
    server.listen(1)

    yield server.getsockname()[1]

    server.close()


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "s3cret")

    return "s3cret"


# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------

def test_discover_without_a_token_is_rejected(client, token):
    response = client.post("/api/discover", json={"url": "https://app.test"})

    assert response.status_code == 401
    assert response.get_json()["success"] is False


def test_discover_with_a_wrong_token_is_rejected(client, token):
    response = client.post(
        "/api/discover",
        json={"url": "https://app.test"},
        headers={"X-API-Key": "wrong"},
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "headers",
    [
        {"X-API-Key": "s3cret"},
        {"Authorization": "Bearer s3cret"},
    ],
)
def test_discover_accepts_either_token_header(client, token, headers):
    response = client.post("/api/discover", json={}, headers=headers)

    # 400 for the missing url, i.e. the request got past authentication.
    assert response.status_code == 400


def test_remote_callers_are_rejected_when_no_token_is_configured(
    client,
    monkeypatch,
):
    monkeypatch.setattr(settings, "API_TOKEN", "")

    response = client.post(
        "/api/discover",
        json={"url": "https://app.test"},
        environ_base=REMOTE,
    )

    assert response.status_code == 401


def test_loopback_is_allowed_when_no_token_is_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "")

    response = client.post("/api/discover", json={})

    assert response.status_code == 400


@pytest.mark.parametrize(
    "header",
    ["X-Forwarded-For", "X-Real-IP", "Forwarded"],
)
def test_proxied_callers_are_rejected_when_no_token_is_configured(
    client,
    monkeypatch,
    header,
):
    monkeypatch.setattr(settings, "API_TOKEN", "")

    response = client.post(
        "/api/discover",
        json={},
        headers={header: "203.0.113.10"},
    )

    assert response.status_code == 401


def test_scans_do_not_go_through_a_proxy():
    session = build_session()

    assert session.trust_env is False
    assert session.proxies == {}

    with pytest.raises(BlockedTargetError):
        session.get_adapter("http://app.test/").proxy_manager_for(
            "http://proxy.test:3128",
        )


def test_delete_requires_a_token(client, token):
    response = client.delete("/api/applications/app-1")

    assert response.status_code == 401


def test_mendix_analysis_requires_a_token(client, token):
    response = client.post("/api/mendix/analyze", json={"model": {}})

    assert response.status_code == 401


def test_reading_findings_stays_open(client, token):
    assert client.get("/api/applications").status_code == 200


# ------------------------------------------------------------------
# Target policy (SSRF)
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/",
    ],
)
def test_non_http_schemes_are_blocked(url):
    with pytest.raises(BlockedTargetError):
        assert_target_allowed(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8099/",
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ],
)
def test_internal_addresses_are_blocked(url):
    with pytest.raises(BlockedTargetError):
        assert_target_allowed(url)


def test_unresolvable_hosts_are_blocked():
    with pytest.raises(BlockedTargetError):
        assert_target_allowed("http://nonexistent.invalid/")


def test_allowlisted_hosts_are_permitted(allow_local_targets):
    assert_target_allowed("http://127.0.0.1:8099/")


def test_private_targets_can_be_enabled(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)

    assert_target_allowed("http://192.168.1.10/")


def test_discover_rejects_an_internal_target(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "")

    response = client.post(
        "/api/discover",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
    )

    payload = response.get_json()

    assert response.status_code == 403
    assert payload["reason"] == "blocked_target"


def test_redirect_hops_are_re_checked():
    class Response:
        url = "http://169.254.169.254/latest/meta-data/"

    with pytest.raises(BlockedTargetError):
        guard_response(Response())


def test_connections_to_internal_addresses_are_refused(listening_port):
    """The connect-time check catches an address the policy never saw."""

    session = build_session()

    with pytest.raises(requests.RequestException) as caught:
        session.get(f"http://127.0.0.1:{listening_port}/", timeout=5)

    assert unwrap_blocked(caught.value) is not None


def test_the_crawler_uses_the_guarded_session():
    assert crawler.build_session is build_session


def test_allowed_redirect_hops_pass(allow_local_targets):
    class Response:
        url = "http://127.0.0.1:8099/next"

    guard_response(Response())


# ------------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------------

def test_scanning_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "")
    monkeypatch.setattr(settings, "RATE_LIMIT_REQUESTS", 2)

    for _ in range(2):
        assert client.post("/api/discover", json={}).status_code == 400

    response = client.post("/api/discover", json={})

    assert response.status_code == 429
    assert response.get_json()["reason"] == "rate_limited"
    assert int(response.headers["Retry-After"]) >= 1


def test_rate_limit_is_per_client(client, token, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_REQUESTS", 1)

    headers = {"X-API-Key": token}

    assert client.post(
        "/api/discover",
        json={},
        headers=headers,
    ).status_code == 400

    assert client.post(
        "/api/discover",
        json={},
        headers=headers,
    ).status_code == 429

    assert client.post(
        "/api/discover",
        json={},
        headers=headers,
        environ_base=REMOTE,
    ).status_code == 400


def test_expired_clients_are_dropped():
    limiter = RateLimiter()

    limiter.check("a:198.51.100.1", limit=5, window=1)

    assert limiter.tracked_clients() == 1

    time.sleep(1.05)

    limiter.check("a:198.51.100.2", limit=5, window=1)

    assert limiter.tracked_clients() == 1


def test_unauthorized_calls_do_not_consume_the_budget(client, token, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_REQUESTS", 1)

    assert client.post("/api/discover", json={}).status_code == 401

    response = client.post(
        "/api/discover",
        json={},
        headers={"X-API-Key": token},
    )

    assert response.status_code == 400
