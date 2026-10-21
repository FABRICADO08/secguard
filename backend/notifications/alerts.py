"""Alert when a scan introduces findings at or above the configured severity."""

from __future__ import annotations

import threading
from typing import Any

from backend.config import settings
from backend.notifications.channels import Message, configured, send
from backend.portfolio.objectives import SEVERITY_RANK, new_findings

MAX_LISTED = 10


def threshold() -> str:
    return settings.ALERT_MIN_SEVERITY if settings.ALERT_MIN_SEVERITY in SEVERITY_RANK else "critical"


def application_link(application_id: str) -> str:
    if not settings.PUBLIC_URL:
        return ""
    return f"{settings.PUBLIC_URL}/application-health.html?application={application_id}"


def new_findings_message(
    name: str,
    application_id: str,
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]],
) -> Message | None:
    """The alert for ``current`` compared with the previous scan, or None when nothing is new."""
    severity = threshold()
    # Every finding of the previous scan is comparable, Mendix model findings included.
    added = new_findings({"findings": current}, {"findings": previous or [], "mendix": {"analyzed": True}}, severity)
    if not added:
        return None
    added.sort(key=lambda finding: -SEVERITY_RANK.get(str(finding.get("severity")), 0))
    scope = "critical" if severity == "critical" else f"{severity} or worse"
    noun = "finding" if len(added) == 1 else "findings"
    when = "in its first scan" if previous is None else "since the previous scan"
    lines = [f"{name} has {len(added)} new {scope} {noun} {when}:"]
    lines += [
        f"- [{str(finding.get('severity', '')).upper()}] {finding.get('title', '')} ({finding.get('location') or 'no location'})"
        for finding in added[:MAX_LISTED]
    ]
    if len(added) > MAX_LISTED:
        lines.append(f"...and {len(added) - MAX_LISTED} more.")
    return Message(title=f"SecGuard: new {scope} {noun} in {name}", lines=lines, link=application_link(application_id))


def _dispatch(message: Message) -> None:
    threading.Thread(target=send, args=(message,), daemon=True).start()


def enabled() -> bool:
    return any(configured().values())


def notify_new_findings(
    name: str,
    application_id: str,
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]],
) -> bool:
    """Queue the alert for delivery; True when one was sent."""
    message = new_findings_message(name, application_id, previous, current)
    if message is None:
        return False
    _dispatch(message)
    return True
