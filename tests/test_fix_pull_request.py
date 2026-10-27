import base64
import json

import pytest

from backend import app as app_module
from backend.repository.scanner import scan_repository
from backend.repository.upgrades import apply_upgrades, plan_upgrades


def _dependency(name, spec, ecosystem="PyPI", manifest="requirements.txt", line=1, **extra):
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": spec.lstrip("=^~ "),
        "spec": spec,
        "manifest": manifest,
        "line": line,
        "direct": True,
        "vulnerabilities": ["GHSA-test"],
        "remediation": {"target": "3.0.0", "breaking": True, "non_breaking_target": "1.2.9", "resolves_all": True},
        **extra,
    }


def test_only_rewritable_direct_declarations_are_planned():
    report = {"dependencies": [
        _dependency("Django", "==1.2.0"),
        _dependency("lodash", "^1.2.0", ecosystem="npm", manifest="web/package.json", line=3),
        _dependency("ranged", ">=1.0", line=2),
        _dependency("locked", "1.2.0", ecosystem="npm", manifest="package-lock.json", line=9),
        _dependency("transitive", "==1.2.0", line=4, direct=False),
        _dependency("unfixable", "==1.2.0", line=5, remediation={"target": ""}),
    ]}

    planned = plan_upgrades(report)

    assert [(item.name, item.new_spec(), item.breaking) for item in planned] == [
        ("Django", "==1.2.9", False),
        ("lodash", "^1.2.9", False),
    ]


def test_every_declaration_on_a_compact_line_is_upgraded():
    upgrades = plan_upgrades({"dependencies": [
        _dependency(name, "1.2.0", ecosystem="npm", manifest="package.json") for name in ("a", "b")
    ]})

    changed, applied = apply_upgrades('{"dependencies": {"a": "1.2.0", "b": "1.2.0"}}', upgrades)

    assert changed == '{"dependencies": {"a": "1.2.9", "b": "1.2.9"}}' and len(applied) == 2


@pytest.mark.parametrize("fix", [
    {"target": "1.3.0\nevil==6.6.6"},
    {"target": "1.2.0"},
    {"target": "latest"},
])
def test_targets_that_are_not_a_newer_release_are_refused(fix):
    assert plan_upgrades({"dependencies": [_dependency("flask", "==1.2.0", remediation=fix)]}) == []
    assert plan_upgrades({"dependencies": [_dependency("bad\nname", "==1.2.0")]}) == []


def test_a_major_upgrade_is_used_only_without_a_non_breaking_fix():
    dependency = _dependency("flask", "==1.2.0", remediation={"target": "3.0.0", "breaking": True})

    [upgrade] = plan_upgrades({"dependencies": [dependency]})

    assert upgrade.target == "3.0.0" and upgrade.breaking is True


def test_declarations_are_rewritten_in_place():
    [requirement] = plan_upgrades({"dependencies": [_dependency("zope.interface", "== 1.2.0", line=2)]})
    text = "flask==2.0\nzope_interface[extra] == 1.2.0 ; python_version > '3'  # web\n"

    changed, applied = apply_upgrades(text, [requirement])

    assert changed == "flask==2.0\nzope_interface[extra] ==1.2.9 ; python_version > '3'  # web\n"
    assert applied == [requirement]


def test_a_changed_declaration_is_left_alone():
    [requirement] = plan_upgrades({"dependencies": [_dependency("django", "==1.2.0")]})

    assert apply_upgrades("django==1.2.5\n", [requirement]) == ("django==1.2.5\n", [])
    assert apply_upgrades("", [requirement]) == ("", [])


class _Response:
    def __init__(self, status, payload=None):
        self.status_code = status
        self.ok = status < 400
        self.content = json.dumps(payload or {}).encode()
        self._payload = payload or {}

    def json(self):
        return self._payload


class _GitHub:
    def __init__(self, files, branch_status=201, pull_status=201):
        self.files = files
        self.branch_status = branch_status
        self.pull_status = pull_status
        self.calls = []

    def __call__(self, method, path, token, **kwargs):
        self.calls.append((method, path, kwargs))
        if method == "GET" and "/contents/" in path:
            manifest = path.split("/contents/", 1)[1]
            if manifest not in self.files:
                return _Response(404)
            return _Response(200, {"sha": "blob", "content": base64.b64encode(self.files[manifest].encode()).decode()})
        if method == "GET":
            return _Response(200, {"object": {"sha": "base-sha"}})
        if path.endswith("/git/refs"):
            return _Response(self.branch_status)
        if method in ("PUT", "DELETE"):
            return _Response(200, {})
        if self.pull_status >= 400:
            return _Response(self.pull_status)
        return _Response(201, {"html_url": "https://github.com/acme/api/pull/7", "number": 7})

    def committed(self):
        return {path.split("/contents/", 1)[1]: base64.b64decode(kwargs["json"]["content"]).decode()
                for method, path, kwargs in self.calls if method == "PUT"}


@pytest.fixture
def stored(client, tmp_path):
    (tmp_path / "app.py").write_text("def main():\n    return 1\n")
    report = scan_repository(tmp_path, {"name": "acme/api", "provider": "github"})
    report["dependencies"] = [
        _dependency("django", "==1.2.0"),
        _dependency("lodash", "^1.2.0", ecosystem="npm", manifest="web/package.json", line=3),
    ]
    response = client.post("/api/repository/scans", json=report)
    assert response.status_code == 201
    return response.get_json()["application_id"]


def _sign_in(monkeypatch, can_trigger=True):
    user = app_module.github_auth.GitHubUser(
        login="bob", name="Bob", avatar_url="", token="secret",
        repositories={"acme/api": {"name": "acme/api", "default_branch": "main", "can_trigger": can_trigger}},
    )
    monkeypatch.setattr(app_module.github_auth, "enabled", lambda: True)
    monkeypatch.setattr(app_module.github_auth, "current_user", lambda: user)
    monkeypatch.setattr(app_module.github_auth, "can_view", lambda application: True)
    return user


def test_a_pull_request_upgrades_every_manifest(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({
        "requirements.txt": "django==1.2.0\n",
        "web/package.json": '{\n  "dependencies": {\n    "lodash": "^1.2.0"\n  }\n}\n',
    })
    monkeypatch.setattr(app_module.github_auth, "_api", github)
    url = f"/api/applications/{stored}/fix-pull-request"

    assert len(client.get(url).get_json()["upgrades"]) == 2
    response = client.post(url)

    assert response.status_code == 201, response.get_json()
    assert response.get_json()["url"] == "https://github.com/acme/api/pull/7"
    _assert_pull_request(github)


def _assert_pull_request(github):
    assert github.committed() == {
        "requirements.txt": "django==1.2.9\n",
        "web/package.json": '{\n  "dependencies": {\n    "lodash": "^1.2.9"\n  }\n}\n',
    }
    pull = next(kwargs["json"] for method, path, kwargs in github.calls if path.endswith("/pulls"))
    assert pull["base"] == "main" and pull["head"].startswith("secguard/upgrade-vulnerable-")
    assert "npm install" in pull["body"] and "GHSA-test" in pull["body"]


def test_an_existing_fix_branch_is_reported(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({"requirements.txt": "django==1.2.0\n", "web/package.json": "{}"}, branch_status=422)
    monkeypatch.setattr(app_module.github_auth, "_api", github)

    response = client.post(f"/api/applications/{stored}/fix-pull-request")

    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]
    assert not github.committed()


def test_a_deleted_manifest_does_not_block_the_others(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({"requirements.txt": "django==1.2.0\n"})
    monkeypatch.setattr(app_module.github_auth, "_api", github)

    response = client.post(f"/api/applications/{stored}/fix-pull-request")

    assert response.status_code == 201
    assert github.committed() == {"requirements.txt": "django==1.2.9\n"}


def test_a_failed_pull_request_deletes_its_branch(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({"requirements.txt": "django==1.2.0\n"}, pull_status=503)
    monkeypatch.setattr(app_module.github_auth, "_api", github)

    response = client.post(f"/api/applications/{stored}/fix-pull-request")

    assert response.status_code == 502
    method, path, _ = github.calls[-1]
    assert method == "DELETE" and path.startswith("/repos/acme/api/git/refs/heads/secguard/upgrade-vulnerable-")


def test_cross_site_requests_are_refused(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({"requirements.txt": "django==1.2.0\n"})
    monkeypatch.setattr(app_module.github_auth, "_api", github)

    response = client.post(f"/api/applications/{stored}/fix-pull-request", headers={"Origin": "https://evil.example"})

    assert response.status_code == 403 and not github.calls


def test_a_stale_scan_opens_nothing(client, stored, monkeypatch):
    _sign_in(monkeypatch)
    github = _GitHub({"requirements.txt": "django==2.0.0\n", "web/package.json": "{}"})
    monkeypatch.setattr(app_module.github_auth, "_api", github)

    response = client.post(f"/api/applications/{stored}/fix-pull-request")

    assert response.status_code == 409
    assert [method for method, _, _ in github.calls] == ["GET", "GET"]


def test_write_access_and_sign_in_are_required(client, stored, monkeypatch):
    url = f"/api/applications/{stored}/fix-pull-request"
    assert client.post(url).status_code == 401

    _sign_in(monkeypatch, can_trigger=False)
    assert client.post(url).status_code == 403
