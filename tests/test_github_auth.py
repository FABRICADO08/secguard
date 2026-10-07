from urllib.parse import parse_qs, urlparse

import pytest

from backend import app as app_module
from backend.config import settings
from backend.repository.scanner import scan_repository
from backend.security import github_auth
from backend.storage import scans


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise github_auth.requests.HTTPError(str(self.status_code))


REPOS = [
    {"full_name": "acme/api", "private": True, "html_url": "https://github.com/acme/api", "default_branch": "main",
     "permissions": {"pull": True, "push": True}},
    {"full_name": "acme/docs", "private": False, "html_url": "https://github.com/acme/docs", "default_branch": "trunk",
     "permissions": {"pull": True, "push": False}},
]


@pytest.fixture
def github(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/login/oauth/access_token"):
            return FakeResponse(payload={"access_token": "gho_test"})
        if url.endswith("/user"):
            return FakeResponse(payload={"login": "octo", "name": "Octo Cat", "avatar_url": ""})
        if url.endswith("/user/repos"):
            return FakeResponse(payload=REPOS)
        if url.endswith("/dispatches"):
            return FakeResponse(204)
        return FakeResponse(404)

    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "secret")
    monkeypatch.setattr(github_auth, "github_request", fake_request)
    return calls


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def ingest(client, tmp_path, name):
    root = tmp_path / name.replace("/", "_")
    root.mkdir()
    (root / "app.py").write_text("def main():\n    return 1\n")
    response = client.post("/api/repository/scans", json=scan_repository(root, {"name": name}))
    assert response.status_code == 201, response.get_json()
    return response.get_json()["application_id"]


def sign_in(client):
    login = client.get("/auth/github/login")
    assert login.status_code == 302
    query = parse_qs(urlparse(login.headers["Location"]).query)
    assert query["code_challenge_method"] == ["S256"] and query["client_id"] == ["client"]
    callback = client.get(f"/auth/github/callback?code=abc&state={query['state'][0]}")
    assert callback.status_code == 302
    return query


def test_login_requires_matching_state(client, github):
    client.get("/auth/github/login")
    assert client.get("/auth/github/callback?code=abc&state=forged").status_code == 400
    assert client.get("/api/auth/me").get_json()["authenticated"] is False


def test_pkce_verifier_is_sent_with_the_code(client, github):
    sign_in(client)
    exchange = next(kwargs for _, url, kwargs in github if url.endswith("/access_token"))
    assert exchange["data"]["code_verifier"] and exchange["data"]["code"] == "abc"
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] and me["user"]["login"] == "octo" and me["user"]["repositories"] == 2


def test_results_only_visible_for_accessible_repositories(client, github, tmp_path):
    visible_id = ingest(client, tmp_path, "acme/api")
    hidden_id = ingest(client, tmp_path, "other/secret")

    assert client.get("/api/repositories").status_code == 401
    assert client.get("/api/applications").get_json()["applications"] == []
    assert client.get(f"/api/applications/{visible_id}/findings").status_code == 404

    sign_in(client)

    listed = {item["id"] for item in client.get("/api/applications").get_json()["applications"]}
    assert listed == {visible_id}
    assert client.get(f"/api/applications/{visible_id}/quality").status_code == 200
    for path in ("", "/findings", "/sbom", "/quality"):
        assert client.get(f"/api/applications/{hidden_id}{path}").status_code == 404

    repositories = client.get("/api/repositories").get_json()["repositories"]
    assert [item["name"] for item in repositories] == ["acme/api", "acme/docs"]
    assert repositories[0]["latest_scan"]["id"] == visible_id
    assert repositories[1]["latest_scan"] is None

    client.post("/auth/logout")
    assert client.get(f"/api/applications/{visible_id}").status_code == 404


def test_manual_scan_dispatches_the_workflow(client, github):
    assert client.post("/api/repositories/acme/api/scan").status_code == 401
    sign_in(client)

    response = client.post("/api/repositories/acme/api/scan")
    assert response.status_code == 202
    method, url, kwargs = github[-1]
    assert method == "POST" and url.endswith("/repos/acme/api/actions/workflows/secguard.yml/dispatches")
    assert kwargs["json"] == {"ref": "main"}

    assert client.post("/api/repositories/acme/docs/scan").status_code == 403
    assert client.post("/api/repositories/other/secret/scan").status_code == 404


def test_without_github_configured_everything_stays_open(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    application_id = ingest(client, tmp_path, "acme/api")
    assert client.get("/auth/github/login").status_code == 404
    assert client.get(f"/api/applications/{application_id}").status_code == 200
    names = [item["name"] for item in client.get("/api/repositories").get_json()["repositories"]]
    assert names == ["acme/api"]
