from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from backend.risk.severity import highest_severity, severity_rank


def build_recommendations(
    findings: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Collapse findings into a prioritized, de-duplicated remediation list.

    Findings produced by the same rule share one recommendation, so the
    list stays actionable instead of repeating per affected URL.
    """

    grouped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        recommendation = str(finding.get("recommendation") or "").strip()

        if not recommendation:
            continue

        rule_id = str(finding.get("rule_id") or recommendation)

        entry = grouped.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "recommendation": recommendation,
                "category": finding.get("category", ""),
                "severity": finding.get("severity", "informational"),
                "finding_count": 0,
                "finding_ids": [],
            },
        )

        entry["finding_count"] += 1
        entry["finding_ids"].append(finding.get("id"))
        entry["severity"] = highest_severity(
            [entry["severity"], finding.get("severity")]
        )

    return sorted(
        grouped.values(),
        key=lambda entry: (
            -severity_rank(entry["severity"]),
            -entry["finding_count"],
            entry["rule_id"],
        ),
    )
