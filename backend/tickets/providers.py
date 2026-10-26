"""Tracker clients. Each knows how to open a ticket, read its state and close or reopen it."""

from __future__ import annotations

import base64
import html
from dataclasses import dataclass
from typing import Protocol

import requests

from backend.config import settings

TIMEOUT = 15

OPEN = "open"
DONE = "done"
WONT_FIX = "wont_fix"

JIRA_WONT_FIX = frozenset({"won't do", "won't fix", "declined", "duplicate", "cannot reproduce", "not a bug"})
JIRA_REJECTION_WORDS = ("won't", "wont", "reject", "declin", "not planned", "cancel")


class TicketError(RuntimeError):
    """The tracker refused or could not be reached."""


@dataclass(frozen=True)
class Draft:
    title: str
    body: str
    repository: str  # owner/name of the application's GitHub repository, or ""


@dataclass(frozen=True)
class Ticket:
    id: str
    url: str
    state: str


class Provider(Protocol):
    name: str
    label: str

    def create(self, draft: Draft) -> Ticket: ...

    def state(self, ticket_id: str) -> str: ...

    def set_state(self, ticket_id: str, state: str, comment: str) -> None: ...


def _checked(response: requests.Response) -> requests.Response:
    if response.status_code >= 400:
        raise TicketError(f"The tracker answered HTTP {response.status_code}.")
    return response


def _call(method: str, url: str, **kwargs: object) -> requests.Response:
    try:
        return _checked(requests.request(method, url, timeout=TIMEOUT, **kwargs))
    except requests.RequestException as error:
        raise TicketError("The tracker could not be reached.") from error


class GitHubIssues:
    name = "github"
    label = "GitHub issue"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {settings.GITHUB_TICKET_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, ticket_id: str, suffix: str = "") -> str:
        repository, _, number = ticket_id.rpartition("#")
        return f"{settings.GITHUB_API_URL}/repos/{repository}/issues/{number}{suffix}"

    def create(self, draft: Draft) -> Ticket:
        if not draft.repository:
            raise TicketError("GitHub issues can only be opened for applications connected to GitHub.")
        issue = _call(
            "POST",
            f"{settings.GITHUB_API_URL}/repos/{draft.repository}/issues",
            headers=self._headers(),
            json={"title": draft.title, "body": draft.body},
        ).json()
        return Ticket(f"{draft.repository}#{issue['number']}", str(issue.get("html_url") or ""), OPEN)

    def state(self, ticket_id: str) -> str:
        issue = _call("GET", self._url(ticket_id), headers=self._headers()).json()
        if issue.get("state") != "closed":
            return OPEN
        return WONT_FIX if issue.get("state_reason") in ("not_planned", "duplicate") else DONE

    def set_state(self, ticket_id: str, state: str, comment: str) -> None:
        if comment:
            _call("POST", self._url(ticket_id, "/comments"), headers=self._headers(), json={"body": comment})
        change = {"state": "open"} if state == OPEN else {
            "state": "closed",
            "state_reason": "not_planned" if state == WONT_FIX else "completed",
        }
        _call("PATCH", self._url(ticket_id), headers=self._headers(), json=change)


def _adf(text: str) -> dict[str, object]:
    """Atlassian document format: one paragraph per line."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}]} if line else {"type": "paragraph"}
            for line in text.splitlines()
        ],
    }


def _category(transition: dict) -> str:
    return str(((transition.get("to") or {}).get("statusCategory") or {}).get("key") or "")


def _rejecting(transition: dict) -> bool:
    names = f"{transition.get('name', '')} {(transition.get('to') or {}).get('name', '')}".lower()
    return any(word in names for word in JIRA_REJECTION_WORDS)


class JiraIssues:
    name = "jira"
    label = "Jira issue"

    def _auth(self) -> tuple[str, str]:
        return settings.JIRA_EMAIL, settings.JIRA_API_TOKEN

    def _api(self, path: str) -> str:
        return f"{settings.JIRA_URL}/rest/api/3{path}"

    def create(self, draft: Draft) -> Ticket:
        fields = {
            "project": {"key": settings.JIRA_PROJECT},
            "issuetype": {"name": settings.JIRA_ISSUE_TYPE},
            "summary": draft.title[:250],
            "description": _adf(draft.body),
            "labels": ["secguard"],
        }
        key = str(_call("POST", self._api("/issue"), auth=self._auth(), json={"fields": fields}).json()["key"])
        return Ticket(key, f"{settings.JIRA_URL}/browse/{key}", OPEN)

    def state(self, ticket_id: str) -> str:
        issue = _call("GET", self._api(f"/issue/{ticket_id}?fields=status,resolution"), auth=self._auth()).json()
        fields = issue.get("fields") or {}
        category = ((fields.get("status") or {}).get("statusCategory") or {}).get("key")
        if category != "done":
            return OPEN
        resolution = str((fields.get("resolution") or {}).get("name") or "").lower()
        rejected = resolution in JIRA_WONT_FIX or resolution == settings.JIRA_WONT_FIX_RESOLUTION.lower()
        return WONT_FIX if rejected else DONE

    def _transition(self, ticket_id: str, state: str) -> dict:
        """The workflow step to the state; a rejection-like step is preferred for not planned."""
        target = "new" if state == OPEN else "done"
        listed = _call(
            "GET", self._api(f"/issue/{ticket_id}/transitions?expand=transitions.fields"), auth=self._auth()
        ).json()
        candidates = [item for item in listed.get("transitions") or [] if _category(item) == target]
        if not candidates:
            raise TicketError(f"The Jira workflow of {ticket_id} has no transition to a '{target}' status.")
        if state == OPEN:
            return candidates[0]
        preferred = [item for item in candidates if _rejecting(item) == (state == WONT_FIX)]
        return (preferred or candidates)[0]

    def set_state(self, ticket_id: str, state: str, comment: str) -> None:
        transition = self._transition(ticket_id, state)
        payload: dict[str, object] = {"transition": {"id": transition["id"]}}
        if state == WONT_FIX and "resolution" in (transition.get("fields") or {}):
            payload["fields"] = {"resolution": {"name": settings.JIRA_WONT_FIX_RESOLUTION}}
        if comment:
            _call("POST", self._api(f"/issue/{ticket_id}/comment"), auth=self._auth(), json={"body": _adf(comment)})
        _call("POST", self._api(f"/issue/{ticket_id}/transitions"), auth=self._auth(), json=payload)


class AzureWorkItems:
    name = "azure"
    label = "Azure DevOps work item"

    def _headers(self, patch: bool = False) -> dict[str, str]:
        token = base64.b64encode(f":{settings.AZURE_DEVOPS_TOKEN}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        if patch:
            headers["Content-Type"] = "application/json-patch+json"
        return headers

    def _item(self, ticket_id: str) -> str:
        return f"{settings.AZURE_DEVOPS_URL}/{settings.AZURE_DEVOPS_PROJECT}/_apis/wit/workitems/{ticket_id}?api-version=7.1"

    def create(self, draft: Draft) -> Ticket:
        body = "<br>".join(html.escape(line) for line in draft.body.splitlines())
        operations = [
            {"op": "add", "path": "/fields/System.Title", "value": draft.title[:250]},
            {"op": "add", "path": "/fields/System.Description", "value": body},
            {"op": "add", "path": "/fields/System.Tags", "value": "SecGuard"},
        ]
        url = (
            f"{settings.AZURE_DEVOPS_URL}/{settings.AZURE_DEVOPS_PROJECT}/_apis/wit/workitems/"
            f"${settings.AZURE_DEVOPS_WORK_ITEM_TYPE}?api-version=7.1"
        )
        item = _call("POST", url, headers=self._headers(patch=True), json=operations).json()
        link = ((item.get("_links") or {}).get("html") or {}).get("href") or ""
        return Ticket(str(item["id"]), str(link), OPEN)

    def state(self, ticket_id: str) -> str:
        item = _call("GET", self._item(ticket_id), headers=self._headers()).json()
        value = str((item.get("fields") or {}).get("System.State") or "")
        if value == settings.AZURE_DEVOPS_WONT_FIX_STATE:
            return WONT_FIX
        return DONE if value in (settings.AZURE_DEVOPS_DONE_STATE, "Done", "Closed", "Resolved") else OPEN

    def set_state(self, ticket_id: str, state: str, comment: str) -> None:
        target = {
            OPEN: settings.AZURE_DEVOPS_OPEN_STATE,
            DONE: settings.AZURE_DEVOPS_DONE_STATE,
            WONT_FIX: settings.AZURE_DEVOPS_WONT_FIX_STATE,
        }[state]
        operations = [{"op": "add", "path": "/fields/System.State", "value": target}]
        if comment:
            operations.append({"op": "add", "path": "/fields/System.History", "value": comment})
        _call("PATCH", self._item(ticket_id), headers=self._headers(patch=True), json=operations)


PROVIDERS: dict[str, Provider] = {
    "github": GitHubIssues(),
    "jira": JiraIssues(),
    "azure": AzureWorkItems(),
}


def missing_settings(name: str) -> list[str]:
    """Server settings the provider still needs."""
    required = {
        "github": {"SECGUARD_GITHUB_TICKET_TOKEN": settings.GITHUB_TICKET_TOKEN},
        "jira": {
            "SECGUARD_JIRA_URL": settings.JIRA_URL,
            "SECGUARD_JIRA_EMAIL": settings.JIRA_EMAIL,
            "SECGUARD_JIRA_API_TOKEN": settings.JIRA_API_TOKEN,
            "SECGUARD_JIRA_PROJECT": settings.JIRA_PROJECT,
        },
        "azure": {
            "SECGUARD_AZURE_DEVOPS_URL": settings.AZURE_DEVOPS_URL,
            "SECGUARD_AZURE_DEVOPS_PROJECT": settings.AZURE_DEVOPS_PROJECT,
            "SECGUARD_AZURE_DEVOPS_TOKEN": settings.AZURE_DEVOPS_TOKEN,
        },
    }.get(name)
    if required is None:
        return ["SECGUARD_TICKET_PROVIDER"]
    missing = [key for key, value in required.items() if not value]
    for key in ("SECGUARD_JIRA_URL", "SECGUARD_AZURE_DEVOPS_URL"):
        value = required.get(key)
        if value and not value.lower().startswith("https://"):
            missing.append(f"{key} (must start with https://)")
    return missing


def active() -> Provider | None:
    """The configured provider when all of its settings are present."""
    name = settings.TICKET_PROVIDER
    if not name or missing_settings(name):
        return None
    return PROVIDERS[name]
