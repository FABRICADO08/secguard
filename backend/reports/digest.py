"""The weekly portfolio digest: current state plus findings introduced in the last week."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from backend.config import settings
from backend.notifications.channels import Message
from backend.portfolio.applications import application_name
from backend.portfolio.objectives import evaluate, new_findings
from backend.security import github_auth
from backend.storage import objectives as objective_store
from backend.storage.scans import list_applications, load_application

DAYS = 7


def _findings(application_id: str) -> list[dict[str, Any]]:
    return (load_application(application_id).get("security") or {}).get("findings") or []


def _scans_by_repository() -> dict[str, list[dict[str, Any]]]:
    scans: dict[str, list[dict[str, Any]]] = {}
    for summary in list_applications():
        if summary.get("platform") != "Repository":
            continue
        key = github_auth.repository_name(summary).lower()
        if key:
            scans.setdefault(key, []).append(summary)
    for history in scans.values():
        history.sort(key=lambda summary: str(summary.get("updated_at") or ""))
    return scans


def _count(findings: list[dict[str, Any]] | None, severity: str) -> int | None:
    return None if findings is None else sum(finding.get("severity") == severity for finding in findings)


def _added_this_week(history: list[dict[str, Any]], cutoff: str) -> list[dict[str, Any]] | None:
    """High and critical findings of the latest scan absent from the newest scan before the cutoff."""
    earlier = [summary for summary in history if str(summary.get("updated_at") or "") <= cutoff]
    first_scan_this_week = str(history[0].get("updated_at") or "") > cutoff
    if not earlier and not first_scan_this_week:
        return None
    # An application first scanned this week is compared with an empty baseline.
    base = {"findings": _findings(earlier[-1]["id"]) if earlier else [], "mendix": {"analyzed": True}}
    return new_findings({"findings": _findings(history[-1]["id"])}, base, "high")


def digest_rows(now: datetime | None = None) -> list[dict[str, Any]]:
    """Per application: latest scan, objective status and findings new since a week ago."""
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=DAYS)).isoformat()
    objectives = objective_store.load()
    rows = []
    for key, history in sorted(_scans_by_repository().items()):
        added = _added_this_week(history, cutoff)
        rows.append(
            {
                "name": application_name(key, history[-1]),
                "latest": history[-1],
                "objectives": evaluate(objectives, history[-1]),
                "new_critical": _count(added, "critical"),
                "new_high": _count(added, "high"),
            }
        )
    return rows


def _open(rows: list[dict[str, Any]], severity: str) -> int:
    return sum((row["latest"].get("severity_counts") or {}).get(severity, 0) for row in rows)


def _summary_line(rows: list[dict[str, Any]]) -> str:
    measured = [row for row in rows if row["objectives"]["met"] is not None]
    meeting = [row for row in measured if row["objectives"]["met"]]
    return f"{len(rows)} applications · {len(meeting)} of {len(measured)} meet the objectives"


def _application_line(row: dict[str, Any]) -> str:
    latest = row["latest"]
    counts = latest.get("severity_counts") or {}
    overall = (latest.get("health") or {}).get("overall") or {}
    health = f"health {overall['score']} ({overall.get('grade', '-')})" if overall.get("score") is not None else "no health score"
    stars = latest.get("maintainability")
    rating = f"{float(stars):.1f} stars" if stars is not None else "no rating"
    status = {True: "objectives met", False: "objectives missed", None: "objectives not measured"}[row["objectives"]["met"]]
    new = "" if row["new_critical"] is None else f", +{row['new_critical']} critical / +{row['new_high']} high this week"
    return f"- {row['name']}: {health}, {rating}, {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {status}{new}"


def digest_message(rows: list[dict[str, Any]]) -> Message:
    new_critical = sum(row["new_critical"] or 0 for row in rows)
    new_high = sum(row["new_high"] or 0 for row in rows)
    lines = [
        _summary_line(rows),
        f"Open: {_open(rows, 'critical')} critical, {_open(rows, 'high')} high · new this week: {new_critical} critical, {new_high} high",
        "",
    ]
    lines += [_application_line(row) for row in rows] or ["No applications have been scanned yet."]
    link = f"{settings.PUBLIC_URL}/applications.html" if settings.PUBLIC_URL else ""
    return Message(title="SecGuard weekly digest", lines=lines, link=link)
