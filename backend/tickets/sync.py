"""Keep tickets and SecGuard finding workflows in step, in both directions."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from backend.config import settings
from backend.portfolio import triage
from backend.portfolio.objectives import SEVERITY_RANK
from backend.portfolio.summary import finding_key
from backend.security import github_auth
from backend.storage import triage as triage_store
from backend.storage.scans import list_applications
from backend.tickets.providers import (
    DONE,
    OPEN,
    WONT_FIX,
    Draft,
    Provider,
    TicketError,
    active,
)

LOG = logging.getLogger(__name__)

FOOTER = (
    "Opened by SecGuard. Closing this ticket as not planned marks the finding as an accepted risk, "
    "and reopening it reopens the finding. When a later scan no longer detects the finding, "
    "SecGuard closes the ticket; if a closed ticket's finding is still detected, SecGuard reopens it."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def actor(provider: Provider, ticket_id: str) -> str:
    return f"{provider.label} {ticket_id}"


def auto_threshold() -> int | None:
    """Lowest severity rank that opens a ticket after a scan, or None when tickets are opened by hand."""
    return SEVERITY_RANK.get(settings.TICKET_MIN_SEVERITY)


def finding_link(application: dict[str, Any], finding: dict[str, Any]) -> str:
    if not settings.PUBLIC_URL:
        return ""
    return (
        f"{settings.PUBLIC_URL}/finding-detail.html?application={application.get('id', '')}"
        f"&finding={finding.get('id', '')}"
    )


def draft(application: dict[str, Any], finding: dict[str, Any]) -> Draft:
    name = str(application.get("name") or "application")
    severity = str(finding.get("severity") or "").capitalize()
    lines = [
        f"Application: {name}",
        f"Severity: {severity}",
        f"Rule: {finding.get('rule_id', '')}",
        f"Location: {finding.get('location') or 'not recorded'}",
        "",
        str(finding.get("description") or ""),
    ]
    if finding.get("recommendation"):
        lines += ["", f"How to fix: {finding['recommendation']}"]
    link = finding_link(application, finding)
    if link:
        lines += ["", f"Details: {link}"]
    lines += ["", FOOTER]
    repository = github_auth.repository_name(application) if application.get("platform") == "Repository" else ""
    return Draft(
        title=f"[SecGuard] {severity}: {finding.get('title', '')} in {name}",
        body="\n".join(lines),
        repository=repository,
    )


def _with_ticket(ticket: dict[str, Any]):
    def change(previous: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        if previous.get("ticket"):
            return previous, ""
        return {**previous, "ticket": ticket}, ""

    return change


def open_ticket(application: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    """The finding's ticket, opened in the configured tracker unless it already has one."""
    provider = active()
    if provider is None:
        raise TicketError("Ticket sync is not configured on this server.")
    system = triage.system_key(application)
    key = finding_key(finding)
    existing = triage_store.load_system(system).get(key, {}).get("ticket")
    if existing:
        return existing
    created = provider.create(draft(application, finding))
    ticket = {"provider": provider.name, "id": created.id, "url": created.url, "state": OPEN, "synced_at": _now()}
    record, _ = triage_store.update_record(system, key, _with_ticket(ticket))
    return (record or {}).get("ticket") or ticket


def desired_state(status: str) -> str:
    return WONT_FIX if status in triage.NEEDS_REASON else OPEN


def _store_state(system: str, key: str, state: str, update: dict[str, str] | None = None, by: str = "") -> None:
    def change(previous: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        if not previous.get("ticket"):
            return None, ""
        record = dict(triage.apply_update(previous, update, by)) if update else dict(previous)
        record["ticket"] = {**previous["ticket"], "state": state, "synced_at": _now()}
        return record, ""

    triage_store.update_record(system, key, change)


def push(system: str, key: str, record: dict[str, Any], by: str) -> str:
    """Move the ticket after someone changed the finding in SecGuard; an error message or ""."""
    ticket = record.get("ticket") or {}
    provider = active()
    if not ticket or provider is None or ticket.get("provider") != provider.name:
        return ""
    status = str(record.get("status") or triage.OPEN)
    target = desired_state(status)
    if target == ticket.get("state"):
        return ""
    label = status.replace("_", " ")
    comment = f"SecGuard: {by} set this finding to {label}."
    if record.get("reason"):
        comment += f" Reason: {record['reason']}"
    try:
        provider.set_state(str(ticket["id"]), target, comment)
    except TicketError:
        LOG.warning("Could not update %s", actor(provider, str(ticket.get("id"))), exc_info=True)
        return f"The {provider.label} could not be updated. The server log has the details."
    _store_state(system, key, target)
    return ""


def remote_update(record: dict[str, Any], state: str, by: str) -> dict[str, str] | None:
    """The SecGuard change a tracker state implies, or None. A completed ticket waits for the next scan."""
    status = str(record.get("status") or triage.OPEN)
    if state == WONT_FIX and status in triage.ACTIVE:
        return {"status": triage.ACCEPTED_RISK, "reason": f"Closed as not planned in {by}."}
    if state == OPEN and status in triage.NEEDS_REASON:
        return {"status": triage.OPEN, "reason": ""}
    return None


def apply_remote(system: str, key: str, record: dict[str, Any], state: str, provider: Provider) -> bool:
    """Record a state read from the tracker; True when the finding's workflow changed."""
    ticket = record.get("ticket") or {}
    if state == ticket.get("state"):
        return False
    by = actor(provider, str(ticket.get("id")))
    update = remote_update(record, state, by)
    _store_state(system, key, state, update, by)
    return update is not None


def latest_application_id(system: str) -> str:
    """The newest scan of a system; only it may close or reopen tickets."""
    newest: dict[str, Any] = {}
    for summary in list_applications():
        if triage.system_key(summary) == system and str(summary.get("updated_at") or "") >= str(
            newest.get("updated_at") or ""
        ):
            newest = summary
    return str(newest.get("id") or "")


def _pull(system: str, records: dict[str, dict[str, Any]], provider: Provider, result: dict[str, int]) -> None:
    for key, record in records.items():
        ticket = record.get("ticket") or {}
        if ticket.get("provider") != provider.name:
            continue
        try:
            state = provider.state(str(ticket["id"]))
        except TicketError:
            LOG.warning("Could not read %s", actor(provider, str(ticket.get("id"))), exc_info=True)
            result["errors"] += 1
            continue
        result["updated"] += apply_remote(system, key, record, state, provider)


def _open_missing(application: dict[str, Any], findings: list[dict[str, Any]], records, result) -> None:
    minimum = auto_threshold()
    if minimum is None:
        return
    for finding in findings:
        record = records.get(finding_key(finding)) or {}
        if record.get("ticket") or (record.get("status") or triage.OPEN) not in triage.ACTIVE:
            continue
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) < minimum:
            continue
        try:
            open_ticket(application, finding)
            result["opened"] += 1
        except TicketError:
            LOG.warning("Could not open a ticket for %s", finding_key(finding), exc_info=True)
            result["errors"] += 1


def _scan_target(detected: bool, record: dict[str, Any]) -> tuple[str, str] | None:
    """Where the newest scan moves a ticket: closed when the finding is gone, reopened when it is back."""
    state = (record.get("ticket") or {}).get("state")
    if not detected and state == OPEN:
        return DONE, "SecGuard: the latest scan no longer detects this finding."
    if detected and state == DONE and (record.get("status") or triage.OPEN) in triage.ACTIVE:
        return OPEN, "SecGuard: the latest scan still detects this finding."
    return None


def _follow_scan(system: str, findings: list[dict[str, Any]], records, provider: Provider, result) -> None:
    detected = {finding_key(finding) for finding in findings}
    for key, record in records.items():
        ticket = record.get("ticket") or {}
        move = _scan_target(key in detected, record) if ticket.get("provider") == provider.name else None
        if move is None:
            continue
        try:
            provider.set_state(str(ticket["id"]), move[0], move[1])
        except TicketError:
            LOG.warning("Could not update %s", actor(provider, str(ticket.get("id"))), exc_info=True)
            result["errors"] += 1
            continue
        _store_state(system, key, move[0])
        result["closed" if move[0] == DONE else "reopened"] += 1


def sync_application(application: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, int]:
    """Read every ticket's state, open missing tickets and, for the newest scan, close or reopen tickets."""
    result = {"updated": 0, "opened": 0, "closed": 0, "reopened": 0, "errors": 0}
    provider = active()
    if provider is None:
        return result
    system = triage.system_key(application)
    _pull(system, triage_store.load_system(system), provider, result)
    if latest_application_id(system) != application.get("id"):
        return result
    _open_missing(application, findings, triage_store.load_system(system), result)
    _follow_scan(system, findings, triage_store.load_system(system), provider, result)
    return result


def sync_in_background(application: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    if active() is not None:
        threading.Thread(target=sync_application, args=(application, findings), daemon=True).start()


def _github_state(issue: dict[str, Any]) -> str:
    if issue.get("state") != "closed":
        return OPEN
    return WONT_FIX if issue.get("state_reason") in ("not_planned", "duplicate") else DONE


def _ticket_record(system: str, ticket_id: str) -> tuple[str, dict[str, Any]] | None:
    for key, record in triage_store.load_system(system).items():
        ticket = record.get("ticket") or {}
        if ticket.get("provider") == "github" and str(ticket.get("id", "")).lower() == ticket_id.lower():
            return key, record
    return None


def apply_github_event(payload: dict[str, Any]) -> bool:
    """Apply a GitHub "issues" webhook event; True when it concerned a SecGuard ticket."""
    provider = active()
    issue = payload.get("issue") or {}
    repository = str((payload.get("repository") or {}).get("full_name") or "")
    if provider is None or provider.name != "github" or not repository or "number" not in issue:
        return False
    system = f"github:{repository.lower()}"
    found = _ticket_record(system, f"{repository}#{issue['number']}")
    if found is None:
        return False
    apply_remote(system, found[0], found[1], _github_state(issue), provider)
    return True
