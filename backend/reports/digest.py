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


def digest_rows(now: datetime | None = None) -> list[dict[str, Any]]:
    """Per application: latest scan, objective status and findings new since a week ago."""
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=DAYS)).isoformat()
    objectives = objective_store.load()
    rows = []
    for key, history in sorted(_scans_by_repository().items()):
        latest = history[-1]
        earlier = [summary for summary in history if str(summary.get("updated_at") or "") <= cutoff]
        added = None
        if earlier:
            base = {"findings": _findings(earlier[-1]["id"]), "mendix": {"analyzed": True}}
            added = new_findings({"findings": _findings(latest["id"])}, base, "high")
        rows.append(
            {
                "name": application_name(key, latest),
                "latest": latest,
                "objectives": evaluate(objectives, latest),
                "new_critical": None if added is None else sum(f.get("severity") == "critical" for f in added),
                "new_high": None if added is None else sum(f.get("severity") == "high" for f in added),
            }
        )
    return rows


def digest_message(rows: list[dict[str, Any]]) -> Message:
    critical = sum((row["latest"].get("severity_counts") or {}).get("critical", 0) for row in rows)
    high = sum((row["latest"].get("severity_counts") or {}).get("high", 0) for row in rows)
    measured = [row for row in rows if row["objectives"]["met"] is not None]
    meeting = [row for row in measured if row["objectives"]["met"]]
    new_critical = sum(row["new_critical"] or 0 for row in rows)
    new_high = sum(row["new_high"] or 0 for row in rows)
    lines = [
        f"{len(rows)} applications · {len(meeting)} of {len(measured)} meet the objectives",
        f"Open: {critical} critical, {high} high · new this week: {new_critical} critical, {new_high} high",
        "",
    ]
    for row in rows:
        latest = row["latest"]
        counts = latest.get("severity_counts") or {}
        overall = (latest.get("health") or {}).get("overall") or {}
        health = f"health {overall['score']} ({overall.get('grade', '-')})" if overall.get("score") is not None else "no health score"
        stars = latest.get("maintainability")
        rating = f"{float(stars):.1f} stars" if stars is not None else "no rating"
        status = {True: "objectives met", False: "objectives missed", None: "objectives not measured"}[row["objectives"]["met"]]
        new = "" if row["new_critical"] is None else f", +{row['new_critical']} critical / +{row['new_high']} high this week"
        lines.append(
            f"- {row['name']}: {health}, {rating}, {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {status}{new}"
        )
    if not rows:
        lines.append("No applications have been scanned yet.")
    link = f"{settings.PUBLIC_URL}/applications.html" if settings.PUBLIC_URL else ""
    return Message(title="SecGuard weekly digest", lines=lines, link=link)
