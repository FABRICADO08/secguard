import hashlib
import hmac
import json

import pytest

from backend import app as app_module
from backend.config import settings
from backend.storage import scans
from backend.storage import triage as triage_store
from backend.tickets import providers, sync

SYSTEM = "github:acme/api"
FINDING = {
    "id": "scan-1-f1",
    "rule_id": "REPO-SEC-001",
    "severity": "high",
    "title": "SQL injection",
    "location": "app.py:2",
    "description": "User input reaches a SQL query.",
    "recommendation": "Use query parameters.",
}
KEY = "REPO-SEC-001|app.py:2|SQL injection"


class Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeGitHub:
    """Issues in acme/api, numbered from 1."""

    def __init__(self):
        self.issues = {}
        self.calls = []
        self.fail = False

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if self.fail:
            return Response(500)
        assert url.startswith("https://api.github.com/repos/acme/api/issues")
        tail = url.removeprefix("https://api.github.com/repos/acme/api/issues").strip("/")
        if method == "POST" and not tail:
            number = len(self.issues) + 1
            self.issues[number] = {"number": number, "state": "open", "state_reason": None,
                                   "html_url": f"https://github.com/acme/api/issues/{number}", **kwargs["json"]}
            return Response(201, self.issues[number])
        number = int(tail.split("/")[0])
        if tail.endswith("/comments"):
            return Response(201, {})
        if method == "PATCH":
            self.issues[number].update(kwargs["json"])
        return Response(200, self.issues[number])


@pytest.fixture
def tracker(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(providers.requests, "request", fake)
    monkeypatch.setattr(settings, "TICKET_PROVIDER", "github")
    monkeypatch.setattr(settings, "GITHUB_TICKET_TOKEN", "test-token")
    monkeypatch.setattr(settings, "GITHUB_API_URL", "https://api.github.com")
    monkeypatch.setattr(settings, "TICKET_MIN_SEVERITY", "high")
    monkeypatch.setattr(settings, "TICKET_WEBHOOK_SECRET", "")
    monkeypatch.setattr(settings, "API_TOKEN", "")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    monkeypatch.setattr(sync, "sync_in_background", lambda application, findings: None)
    return fake


@pytest.fixture
def client(tmp_path, monkeypatch, tracker):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def store(application_id, findings, updated_at="2026-10-01T00:00:00+00:00"):
    scans.save_application({
        "id": application_id,
        "name": "Customer API",
        "platform": "Repository",
        "status": "analyzed",
        "updated_at": updated_at,
        "repository": {"repository": {"name": "acme/api"}},
    })
    scans.save_json(
        scans.application_directory(application_id) / "findings.json",
        {"application_id": application_id, "findings": [{**finding, "id": f"{application_id}-f1"} for finding in findings]},
    )
    return scans.load_application(application_id)


def record():
    return triage_store.load_system(SYSTEM).get(KEY, {})


def test_apply_update_keeps_the_ticket():
    from backend.portfolio import triage

    previous = {"status": "open", "ticket": {"id": "acme/api#1"}}
    updated = triage.apply_update(previous, {"status": "in_progress"}, "octo")
    assert updated["ticket"] == {"id": "acme/api#1"} and updated["status"] == "in_progress"


def test_open_ticket_from_the_finding_page(client, tracker):
    store("scan-1", [FINDING])

    response = client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")

    assert response.status_code == 201, response.get_json()
    ticket = response.get_json()["workflow"]["ticket"]
    assert ticket["id"] == "acme/api#1" and ticket["state"] == "open"
    issue = tracker.issues[1]
    assert issue["title"] == "[SecGuard] High: SQL injection in Customer API"
    assert "Use query parameters." in issue["body"]
    again = client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")
    assert again.get_json()["workflow"]["ticket"]["id"] == "acme/api#1"
    assert len(tracker.issues) == 1


def test_ticket_routes_need_write_access(client, monkeypatch):
    store("scan-1", [FINDING])
    monkeypatch.setattr(settings, "API_TOKEN", "server-token")

    assert client.post("/api/applications/scan-1/findings/scan-1-f1/ticket").status_code == 403
    assert client.post("/api/applications/scan-1/tickets/sync").status_code == 403
    assert client.post("/api/tickets/sync").status_code == 403


def test_unconfigured_provider_is_reported(client, monkeypatch):
    store("scan-1", [FINDING])
    monkeypatch.setattr(settings, "GITHUB_TICKET_TOKEN", "")

    response = client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")
    assert response.status_code == 409
    payload = client.get("/api/tickets").get_json()
    assert payload["configured"] is False and payload["missing"] == ["SECGUARD_GITHUB_TICKET_TOKEN"]
    assert "test-token" not in json.dumps(payload)


def test_accepting_the_risk_closes_the_ticket_as_not_planned(client, tracker):
    store("scan-1", [FINDING])
    client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")

    response = client.put(
        "/api/applications/scan-1/findings/scan-1-f1/workflow",
        json={"status": "accepted_risk", "reason": "Internal tool only"},
    )

    payload = response.get_json()
    assert payload["ticket_error"] == ""
    assert payload["workflow"]["ticket"]["state"] == "wont_fix"
    assert tracker.issues[1]["state"] == "closed" and tracker.issues[1]["state_reason"] == "not_planned"
    comment = next(body for method, url, body in tracker.calls if url.endswith("/comments"))
    assert "accepted risk" in comment["body"] and "Internal tool only" in comment["body"]

    client.put("/api/applications/scan-1/findings/scan-1-f1/workflow", json={"status": "open"})
    assert tracker.issues[1]["state"] == "open"


def test_tracker_failure_does_not_lose_the_workflow_change(client, tracker):
    store("scan-1", [FINDING])
    client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")
    tracker.fail = True

    response = client.put(
        "/api/applications/scan-1/findings/scan-1-f1/workflow",
        json={"status": "false_positive", "reason": "Sanitised upstream"},
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["workflow"]["status"] == "false_positive"
    assert payload["workflow"]["ticket"]["state"] == "open"
    assert "could not be updated" in payload["ticket_error"]


def test_closing_the_issue_as_not_planned_accepts_the_risk(client, tracker):
    application = store("scan-1", [FINDING])
    client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")
    tracker.issues[1].update(state="closed", state_reason="not_planned")
    calls = len(tracker.calls)

    result = sync.sync_application(application, scans.load_json(
        scans.application_directory("scan-1") / "findings.json")["findings"])

    assert result["updated"] == 1
    assert record()["status"] == "accepted_risk"
    assert record()["updated_by"] == "GitHub issue acme/api#1"
    assert record()["reason"] == "Closed as not planned in GitHub issue acme/api#1."
    assert not [call for call in tracker.calls[calls:] if call[0] != "GET"]

    tracker.issues[1].update(state="open", state_reason="reopened")
    sync.sync_application(application, [FINDING])
    assert record().get("status", "open") == "open"


def test_scan_opens_closes_and_reopens_tickets(client, tracker):
    first = store("scan-1", [FINDING, {**FINDING, "rule_id": "REPO-MNT-001", "severity": "low"}])
    findings = scans.load_json(scans.application_directory("scan-1") / "findings.json")["findings"]

    assert sync.sync_application(first, findings)["opened"] == 1
    assert len(tracker.issues) == 1

    fixed = store("scan-2", [], updated_at="2026-10-02T00:00:00+00:00")
    assert sync.sync_application(fixed, [])["closed"] == 1
    assert tracker.issues[1]["state_reason"] == "completed"
    assert record().get("status", "open") == "open"

    back = store("scan-3", [FINDING], updated_at="2026-10-03T00:00:00+00:00")
    assert sync.sync_application(back, [FINDING])["reopened"] == 1
    assert tracker.issues[1]["state"] == "open"


def test_an_older_scan_never_closes_tickets(client, tracker):
    old = store("scan-1", [])
    store("scan-2", [FINDING], updated_at="2026-10-02T00:00:00+00:00")
    client.post("/api/applications/scan-2/findings/scan-2-f1/ticket")

    assert sync.sync_application(old, [])["closed"] == 0
    assert tracker.issues[1]["state"] == "open"


def test_github_webhook_applies_issue_changes(client, tracker, monkeypatch):
    store("scan-1", [FINDING])
    client.post("/api/applications/scan-1/findings/scan-1-f1/ticket")
    monkeypatch.setattr(settings, "TICKET_WEBHOOK_SECRET", "hook-secret")
    body = json.dumps({
        "action": "closed",
        "issue": {"number": 1, "state": "closed", "state_reason": "not_planned"},
        "repository": {"full_name": "acme/api"},
    }).encode()
    signature = "sha256=" + hmac.new(b"hook-secret", body, hashlib.sha256).hexdigest()
    headers = {"X-GitHub-Event": "issues", "Content-Type": "application/json"}

    forged = client.post("/api/tickets/github/webhook", data=body,
                         headers={**headers, "X-Hub-Signature-256": "sha256=bad"})
    assert forged.status_code == 401
    assert record().get("status", "open") == "open"

    response = client.post("/api/tickets/github/webhook", data=body,
                           headers={**headers, "X-Hub-Signature-256": signature})
    assert response.get_json() == {"success": True, "applied": True}
    assert record()["status"] == "accepted_risk"


def test_jira_states_and_transitions(monkeypatch):
    calls = []
    issue = {"fields": {"status": {"statusCategory": {"key": "done"}}, "resolution": {"name": "Won't Do"}}}
    transitions = {"transitions": [{"id": "11", "to": {"statusCategory": {"key": "new"}}},
                                   {"id": "31", "to": {"statusCategory": {"key": "done"}}}]}

    def fake(method, url, **kwargs):
        calls.append((method, url, kwargs.get("json")))
        return Response(200, transitions if url.endswith("/transitions") else issue)

    monkeypatch.setattr(providers.requests, "request", fake)
    monkeypatch.setattr(settings, "JIRA_URL", "https://acme.atlassian.net")
    jira = providers.JiraIssues()

    assert jira.state("SEC-4") == providers.WONT_FIX
    issue["fields"]["resolution"] = {"name": "Done"}
    assert jira.state("SEC-4") == providers.DONE
    jira.set_state("SEC-4", providers.OPEN, "")
    assert calls[-1] == ("POST", "https://acme.atlassian.net/rest/api/3/issue/SEC-4/transitions",
                         {"transition": {"id": "11"}})


def test_azure_states(monkeypatch):
    state = {"value": "Removed"}
    calls = []

    def fake(method, url, **kwargs):
        calls.append((method, url, kwargs.get("json")))
        return Response(200, {"fields": {"System.State": state["value"]}})

    monkeypatch.setattr(providers.requests, "request", fake)
    monkeypatch.setattr(settings, "AZURE_DEVOPS_URL", "https://dev.azure.com/acme")
    monkeypatch.setattr(settings, "AZURE_DEVOPS_PROJECT", "Portal")
    azure = providers.AzureWorkItems()

    assert azure.state("42") == providers.WONT_FIX
    state["value"] = "Closed"
    assert azure.state("42") == providers.DONE
    state["value"] = "Active"
    assert azure.state("42") == providers.OPEN
    azure.set_state("42", providers.DONE, "Fixed")
    assert calls[-1][2] == [{"op": "add", "path": "/fields/System.State", "value": "Closed"},
                            {"op": "add", "path": "/fields/System.History", "value": "Fixed"}]
