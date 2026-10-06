"""
Aggregate health: one 0-100 score per aspect (security, open-source
health, maintainability), an overall score, an A-F grade and a star
rating, so a repository can be summarised and benchmarked at a glance.
"""

from __future__ import annotations

from statistics import median
from typing import Any

from backend.portfolio.summary import rating_for
from backend.risk.scoring import application_risk_score

WEIGHTS = {"security": 0.4, "open_source": 0.3, "maintainability": 0.3}

_DEPENDENCY_PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 0}


def grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _clamp(value: float) -> int:
    return round(min(max(value, 0.0), 100.0))


def _aspect(score: float) -> dict[str, Any]:
    score = _clamp(score)

    return {"score": score, "grade": grade(score), "stars": rating_for(100 - score)}


def security_health(findings: list[dict[str, Any]]) -> int:
    exploitable = [
        finding
        for finding in findings
        if finding.get("rule_id") in ("REPO-DEP-001", "REPO-SUP-001", "REPO-SUP-002")
    ]

    return _clamp(100 - application_risk_score(exploitable))


def open_source_health(findings: list[dict[str, Any]], freshness: dict[str, Any]) -> int:
    penalty = 0.0

    for finding in findings:
        rule = str(finding.get("rule_id") or "")
        severity = str(finding.get("severity") or "low")

        if rule == "REPO-DEP-001":
            penalty += _DEPENDENCY_PENALTY.get(severity, 3) * 0.5
        elif rule.startswith("REPO-LIC-") or rule in ("REPO-DEP-002", "REPO-DEP-003", "REPO-DEP-004"):
            penalty += _DEPENDENCY_PENALTY.get(severity, 3) * 0.6
        elif rule == "REPO-DEP-005":
            penalty += 1.5

    index = freshness.get("freshness_index")

    if index is not None:
        penalty += (100 - index) * 0.2

    return _clamp(100 - min(penalty, 100))


def maintainability_health(metrics: dict[str, Any]) -> int:
    penalty = float(metrics.get("complex_code_ratio") or 0) * 60
    penalty += float(metrics.get("duplication_ratio") or 0) * 150

    docstrings = metrics.get("docstring_coverage")
    annotations = metrics.get("type_annotation_coverage")

    if docstrings is not None:
        penalty += (1 - docstrings) * 15

    if annotations is not None:
        penalty += (1 - annotations) * 10

    if not metrics.get("has_readme", True):
        penalty += 5

    if metrics.get("has_web_api") and not metrics.get("api_specs"):
        penalty += 3

    return _clamp(100 - penalty)


def health_summary(
    findings: list[dict[str, Any]],
    freshness: dict[str, Any],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    aspects = {
        "security": security_health(findings),
        "open_source": open_source_health(findings, freshness),
        "maintainability": maintainability_health(metrics),
    }

    overall = sum(aspects[name] * weight for name, weight in WEIGHTS.items())

    # A critical exposure cannot be averaged away by tidy code.
    overall = min(overall, aspects["security"] + 20)

    return {
        "overall": _aspect(overall),
        **{name: _aspect(score) for name, score in aspects.items()},
    }


def benchmark(scores: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Percentile rank and distance from the portfolio median per repository."""

    if not scores:
        return {}

    values = sorted(scores.values())
    middle = median(values)

    return {
        key: {
            "percentile": round(100 * sum(1 for value in values if value <= score) / len(values)),
            "delta_from_median": round(score - middle, 1),
            "portfolio_median": middle,
        }
        for key, score in scores.items()
    }
