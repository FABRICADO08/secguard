from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from backend.risk.severity import (
    empty_severity_counts,
    normalize_severity,
)

# Stars are the portfolio-level shorthand for the 0-100 risk score: a
# clean system earns the full five, the worst reachable score keeps half
# a star so the rating never collapses to nothing.
BEST_RATING = 5.0
WORST_RATING = 0.5

TREND_MONTHS = 12


def rating_for(score: Any) -> float:
    """Translate a 0-100 risk score into a 0.5-5.0 star rating."""

    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0.0

    value = min(max(value, 0.0), 100.0)

    span = BEST_RATING - WORST_RATING

    return round(BEST_RATING - (value / 100.0) * span, 1)


def lineage_key(application: dict[str, Any]) -> str:
    """
    Identify the system a scan belongs to.

    Every scan writes its own application record, so repeated scans of
    one target are only recognisable by the target they addressed.
    """

    for field in ("url", "final_url", "requested_url", "name"):
        value = str(application.get(field) or "").strip().lower()

        if value:
            return value.rstrip("/")

    return str(application.get("id") or "")


def finding_key(finding: dict[str, Any]) -> str:
    """Identity of a finding across scans of the same system."""

    return "|".join(
        str(finding.get(field) or "")
        for field in ("rule_id", "location", "title")
    )


def _scan_moment(application: dict[str, Any]) -> str:
    return str(
        application.get("updated_at")
        or application.get("created_at")
        or ""
    )


def _month_of(moment: str) -> str:
    return moment[:7]


def _counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = empty_severity_counts()

    for finding in findings:
        counts[normalize_severity(finding.get("severity"))] += 1

    return counts


def _deltas(
    current: dict[str, int],
    previous: dict[str, int] | None,
) -> dict[str, int]:
    if previous is None:
        return {key: 0 for key in current}

    return {
        key: value - previous.get(key, 0)
        for key, value in current.items()
    }


def _activity(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None,
) -> dict[str, int]:
    """Split the latest findings into new, existing and resolved."""

    keys = {finding_key(finding) for finding in current}

    if previous is None:
        return {
            "new": len(current),
            "existing": 0,
            "resolved": 0,
        }

    previous_keys = {finding_key(finding) for finding in previous}

    return {
        "new": len(keys - previous_keys),
        "existing": len(keys & previous_keys),
        "resolved": len(previous_keys - keys),
    }


def _recent_months(
    today: datetime,
    months: int,
) -> list[str]:
    year = today.year
    month = today.month

    labels = []

    for _ in range(months):
        labels.append(f"{year:04d}-{month:02d}")

        month -= 1

        if month == 0:
            month = 12
            year -= 1

    return list(reversed(labels))


def portfolio_summary(
    applications: list[dict[str, Any]],
    findings_for: Callable[[str], list[dict[str, Any]]],
    today: datetime | None = None,
    months: int = TREND_MONTHS,
) -> dict[str, Any]:
    """
    Fold every stored scan into one portfolio view.

    Scans of the same target form a lineage: the newest is the system's
    current state, and comparing it with its predecessor is what makes
    "new", "existing" and "resolved" answerable.
    """

    today = today or datetime.now(timezone.utc)

    lineages: dict[str, list[dict[str, Any]]] = {}

    for application in applications:
        lineages.setdefault(
            lineage_key(application),
            [],
        ).append(application)

    systems = []
    trend: dict[str, dict[str, int]] = {
        label: {"new": 0, "existing": 0, "resolved": 0}
        for label in _recent_months(today, months)
    }

    for scans in lineages.values():
        scans.sort(key=_scan_moment)

        history: list[dict[str, Any]] | None = None

        for scan in scans:
            findings = findings_for(str(scan.get("id") or ""))

            activity = _activity(findings, history)

            month = _month_of(_scan_moment(scan))

            if month in trend:
                for key, value in activity.items():
                    trend[month][key] += value

            scan["_findings"] = findings
            scan["_activity"] = activity
            scan["_previous"] = history

            history = findings

        latest = scans[-1]

        counts = _counts(latest["_findings"])

        previous = latest["_previous"]

        systems.append(
            {
                "id": latest.get("id"),
                "name": latest.get("name"),
                "url": latest.get("url") or latest.get("final_url"),
                "platform": latest.get("platform", "Unknown"),
                "status": latest.get("status", "unknown"),
                "scan_date": _scan_moment(latest),
                "scan_count": len(scans),
                "risk_score": latest.get("risk_score", 0),
                "risk_grade": latest.get("risk_grade", ""),
                "rating": rating_for(latest.get("risk_score", 0)),
                "total_findings": len(latest["_findings"]),
                "severity_counts": counts,
                "severity_deltas": _deltas(
                    counts,
                    _counts(previous) if previous is not None else None,
                ),
                "activity": latest["_activity"],
                "history": [
                    {
                        "id": scan.get("id"),
                        "scan_date": _scan_moment(scan),
                        "risk_score": scan.get("risk_score", 0),
                        "total_findings": len(scan["_findings"]),
                    }
                    for scan in scans
                ],
            }
        )

    systems.sort(
        key=lambda system: (
            -int(system.get("risk_score") or 0),
            str(system.get("name") or ""),
        )
    )

    totals = empty_severity_counts()

    for system in systems:
        for severity, count in system["severity_counts"].items():
            totals[severity] += count

    ratings = [system["rating"] for system in systems]

    return {
        "generated_at": today.isoformat(),
        "systems": systems,
        "totals": {
            "systems": len(systems),
            "findings": sum(
                system["total_findings"] for system in systems
            ),
            "severity_counts": totals,
            "rating": (
                round(sum(ratings) / len(ratings), 1)
                if ratings
                else BEST_RATING
            ),
            "activity": {
                key: sum(
                    system["activity"][key] for system in systems
                )
                for key in ("new", "existing", "resolved")
            },
        },
        "trend": [
            {"month": month, **values}
            for month, values in trend.items()
        ],
    }
