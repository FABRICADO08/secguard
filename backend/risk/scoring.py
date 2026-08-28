from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from backend.risk.confidence import confidence_multiplier
from backend.risk.severity import (
    base_score,
    empty_severity_counts,
    highest_severity,
    normalize_severity,
    severity_from_score,
)

# Each additional finding contributes progressively less to the
# application score, so a site with many low findings never outranks a
# site with a single critical one.
DECAY = 0.35


def finding_score(
    severity: Any,
    confidence: Any = None,
) -> int:
    """Score a single finding on a 0-100 scale."""

    score = base_score(severity) * confidence_multiplier(confidence)

    return round(min(score, 100))


def severity_counts(
    findings: Iterable[dict[str, Any]],
) -> dict[str, int]:

    counts = empty_severity_counts()

    for finding in findings:
        counts[normalize_severity(finding.get("severity"))] += 1

    return counts


def application_risk_score(
    findings: Iterable[dict[str, Any]],
) -> int:
    """
    Aggregate findings into a single 0-100 application risk score.

    The worst finding sets the floor; every further finding adds a
    decaying contribution on top of it.
    """

    scores = sorted(
        (
            int(
                (finding.get("risk") or {}).get("score")
                or finding_score(
                    finding.get("severity"),
                    finding.get("confidence"),
                )
            )
            for finding in findings
        ),
        reverse=True,
    )

    if not scores:
        return 0

    total = float(scores[0])

    for index, score in enumerate(scores[1:], start=1):
        total += score * (DECAY ** index)

    return round(min(total, 100))


def risk_grade(score: int) -> str:
    if score >= 85:
        return "E"

    if score >= 65:
        return "D"

    if score >= 40:
        return "C"

    if score >= 20:
        return "B"

    return "A"


def summarize(
    findings: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build the risk summary attached to an application."""

    findings = list(findings)

    score = application_risk_score(findings)

    return {
        "risk_score": score,
        "risk_severity": severity_from_score(score),
        "risk_grade": risk_grade(score),
        "highest_severity": highest_severity(
            finding.get("severity") for finding in findings
        ),
        "total_findings": len(findings),
        "severity_counts": severity_counts(findings),
    }
