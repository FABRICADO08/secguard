"""Finding workflow: status, owner, due date by severity and an audit trail."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from backend.portfolio.summary import finding_key, lineage_key

OPEN = "open"
IN_PROGRESS = "in_progress"
FALSE_POSITIVE = "false_positive"
ACCEPTED_RISK = "accepted_risk"
STATUSES = (OPEN, IN_PROGRESS, FALSE_POSITIVE, ACCEPTED_RISK)
ACTIVE = frozenset({OPEN, IN_PROGRESS})
NEEDS_REASON = frozenset({FALSE_POSITIVE, ACCEPTED_RISK})

SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}

MAX_TEXT = 500
MAX_OWNER = 100
MAX_HISTORY = 200
FIELDS = ("status", "owner", "due_date", "reason")


def system_key(application: dict[str, Any]) -> str:
    """Decisions follow the system, so a rename or a new scan keeps them."""
    if application.get("platform") == "Repository":
        repository = application.get("repository")
        if isinstance(repository, dict):
            repository = (repository.get("repository") or {}).get("name")
        if repository:
            return f"github:{str(repository).lower()}"
    return lineage_key(application)


def _detected(finding: dict[str, Any]) -> date | None:
    try:
        return datetime.fromisoformat(str(finding.get("detected_at") or "")).date()
    except ValueError:
        return None


def sla_due(finding: dict[str, Any]) -> str:
    days = SLA_DAYS.get(str(finding.get("severity") or "").lower())
    detected = _detected(finding)
    if days is None or detected is None:
        return ""
    return (detected + timedelta(days=days)).isoformat()


def _overdue(due: str, status: str, today: date) -> bool:
    return bool(due) and status in ACTIVE and due < today.isoformat()


def workflow(finding: dict[str, Any], record: dict[str, Any] | None, today: date) -> dict[str, Any]:
    record = record or {}
    status = record.get("status") or OPEN
    deadline = sla_due(finding)
    due = record.get("due_date") or deadline
    return {
        "status": status,
        "due_date": due,
        "sla_due_date": deadline,
        "overdue": _overdue(due, status, today),
        "history": record.get("history") or [],
        **{field: record.get(field) or "" for field in ("owner", "reason", "updated_at", "updated_by")},
    }


def annotate(
    findings: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    today: date | None = None,
) -> list[dict[str, Any]]:
    today = today or datetime.now(timezone.utc).date()
    return [
        {**finding, "workflow": workflow(finding, records.get(finding_key(finding)), today)}
        for finding in findings
    ]


def _text(value: object, field: str, limit: int) -> tuple[str, str]:
    if not isinstance(value, str):
        return "", f"'{field}' must be text."
    value = " ".join(value.split())
    if len(value) > limit:
        return "", f"'{field}' can have at most {limit} characters."
    return value, ""


def _due_date(value: object) -> tuple[str, str]:
    text, problem = _text(value, "due_date", 10)
    if text and not problem:
        try:
            date.fromisoformat(text)
        except ValueError:
            return "", "'due_date' must be a date like 2026-12-31."
    return text, problem


def _field_value(field: str, value: object) -> tuple[str, str]:
    if field == "status":
        if value in STATUSES:
            return str(value), ""
        return "", f"'status' must be one of: {', '.join(STATUSES)}."
    if field == "due_date":
        return _due_date(value)
    return _text(value, field, MAX_OWNER if field == "owner" else MAX_TEXT)


def clean_update(payload: object, previous: dict[str, Any]) -> tuple[dict[str, str], str]:
    """The validated workflow change and "", or {} and the problem.

    Omitted fields keep their previous value.
    """
    if not isinstance(payload, dict):
        return {}, "Send the workflow change as a JSON object."
    merged = {field: str(previous.get(field) or "") for field in FIELDS}
    merged["status"] = merged["status"] or OPEN
    for field in FIELDS:
        if field in payload:
            merged[field], problem = _field_value(field, payload[field])
            if problem:
                return {}, problem
    if merged["status"] in NEEDS_REASON and not merged["reason"]:
        return {}, "Give a reason when marking a finding as a false positive or an accepted risk."
    return merged, ""


def apply_update(
    previous: dict[str, Any],
    update: dict[str, str],
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """New record with an audit entry listing what changed, by whom and when."""
    moment = (now or datetime.now(timezone.utc)).isoformat()
    changes = {
        field: {"from": str(previous.get(field) or (OPEN if field == "status" else "")), "to": value}
        for field, value in update.items()
        if str(previous.get(field) or (OPEN if field == "status" else "")) != value
    }
    if not changes:
        return previous
    history = list(previous.get("history") or [])
    history = (history + [{"at": moment, "by": actor, "changes": changes}])[-MAX_HISTORY:]
    return {**update, "updated_at": moment, "updated_by": actor, "history": history}
