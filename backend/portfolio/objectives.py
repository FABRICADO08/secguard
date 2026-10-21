"""
Portfolio objectives and the pull-request gate.

Objectives are targets every application should meet ("no critical
findings", "at least 3.5 maintainability stars"). The gate compares a
pull request's scan with its base branch and fails only when the change
makes things worse, so existing debt never blocks unrelated work.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

MAX_CRITICAL = "max_critical"
MAX_HIGH = "max_high"
MIN_MAINTAINABILITY = "min_maintainability"
MIN_HEALTH = "min_health"

# Objective id -> (label, kind, lowest allowed value, highest allowed value).
CATALOGUE: dict[str, tuple[str, str, float, float]] = {
    MAX_CRITICAL: ("Critical findings at most", "count", 0, 10000),
    MAX_HIGH: ("High findings at most", "count", 0, 10000),
    MIN_MAINTAINABILITY: ("Maintainability at least (stars)", "stars", 0.5, 5.5),
    MIN_HEALTH: ("Health score at least", "score", 0, 100),
}

DEFAULTS: dict[str, float | None] = {
    MAX_CRITICAL: 0,
    MAX_HIGH: None,
    MIN_MAINTAINABILITY: None,
    MIN_HEALTH: None,
}

_MAXIMUMS = frozenset({MAX_CRITICAL, MAX_HIGH})


def _number(name: str, value: object) -> tuple[float | None, str]:
    label, kind, low, high = CATALOGUE[name]
    if value is None or value == "":
        return None, ""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None, f"{label} must be a number."
    try:
        number = float(value)
    except ValueError:
        return None, f"{label} must be a number."
    if not low <= number <= high:
        return None, f"{label} must be between {low:g} and {high:g}."
    if kind == "stars":
        return round(number, 1), ""
    if number != int(number):
        return None, f"{label} must be a whole number."
    return int(number), ""


def clean(payload: object) -> tuple[dict[str, float | None], str]:
    """Validate an objectives update; an empty value switches an objective off."""
    if not isinstance(payload, dict):
        return {}, "Send the objectives as a JSON object."
    unknown = sorted(set(payload) - set(CATALOGUE))
    if unknown:
        return {}, f"Unknown objective: {unknown[0]}."
    objectives: dict[str, float | None] = {}
    for name in CATALOGUE:
        value, problem = _number(name, payload.get(name))
        if problem:
            return {}, problem
        objectives[name] = value
    return objectives, ""


def report_summary(report: dict[str, Any]) -> dict[str, Any]:
    """The fields of a scanner report that objectives are measured on."""
    return {
        "severity_counts": (report.get("summary") or {}).get("severity_counts") or {},
        "maintainability": (report.get("maintainability") or {}).get("rating"),
        "health": report.get("health") or {},
    }


def _actual(name: str, scan: dict[str, Any]) -> float | None:
    counts = scan.get("severity_counts") or {}
    if name == MAX_CRITICAL:
        return counts.get("critical", 0)
    if name == MAX_HIGH:
        return counts.get("high", 0)
    if name == MIN_MAINTAINABILITY:
        return scan.get("maintainability")
    return ((scan.get("health") or {}).get("overall") or {}).get("score")


def evaluate(objectives: dict[str, Any], scan: dict[str, Any]) -> dict[str, Any]:
    """
    Check one scan summary against the objectives.

    ``met`` is ``None`` when no objective could be measured (for example a
    maintainability target on a scan without a rating).
    """
    results = []
    for name, target in objectives.items():
        if target is None or name not in CATALOGUE:
            continue
        actual = _actual(name, scan)
        met = None if actual is None else actual <= target if name in _MAXIMUMS else actual >= target
        results.append({"id": name, "label": CATALOGUE[name][0], "target": target, "actual": actual, "met": met})
    measured = [result["met"] for result in results if result["met"] is not None]
    return {"met": all(measured) if measured else None, "results": results}


def _identity(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Rule, file and title: line numbers move whenever code above them changes."""
    location = str(finding.get("location") or "")
    path, _, line = location.rpartition(":")
    if not (path and line.isdigit()):
        path = location
    return str(finding.get("rule_id") or ""), path, str(finding.get("title") or "")


def _gated(findings: list[dict[str, Any]], threshold: int, skip_mendix: bool) -> list[dict[str, Any]]:
    return [
        finding
        for finding in findings
        if SEVERITY_RANK.get(str(finding.get("severity") or ""), 0) >= threshold
        and not (skip_mendix and str(finding.get("rule_id") or "").startswith("MXSEC-"))
    ]


def new_findings(
    head: dict[str, Any],
    base: dict[str, Any],
    severity: str = "high",
) -> list[dict[str, Any]]:
    """Findings at or above ``severity`` the pull request adds to its base branch."""
    threshold = SEVERITY_RANK[severity]
    # A base scan without a Mendix export cannot tell which model findings are new.
    skip_mendix = "mendix" not in base
    remaining = Counter(_identity(finding) for finding in _gated(base.get("findings") or [], threshold, skip_mendix))
    added = []
    for finding in _gated(head.get("findings") or [], threshold, skip_mendix):
        key = _identity(finding)
        if remaining[key]:
            remaining[key] -= 1
        else:
            added.append(finding)
    return added


def gate(
    head: dict[str, Any],
    base: dict[str, Any],
    objectives: dict[str, Any],
    severity: str = "high",
    max_rating_drop: float = 0.2,
) -> dict[str, Any]:
    """Fail when the pull request adds findings, lowers maintainability or newly misses an objective."""
    problems = []
    added = new_findings(head, base, severity) if severity != "none" else []
    if added:
        problems.append(f"{len(added)} new finding(s) at or above {severity} severity.")

    head_summary, base_summary = report_summary(head), report_summary(base)
    before, after = base_summary["maintainability"], head_summary["maintainability"]
    if before is not None and after is not None and after < before - max_rating_drop:
        problems.append(f"Maintainability drops from {before:.1f} to {after:.1f} stars.")

    was = {result["id"]: result["met"] for result in evaluate(objectives, base_summary)["results"]}
    for result in evaluate(objectives, head_summary)["results"]:
        if result["met"] is False and was.get(result["id"]) is not False:
            problems.append(f"Objective missed: {result['label']} {result['target']:g} (now {result['actual']:g}).")

    return {
        "passed": not problems,
        "problems": problems,
        "new_findings": added,
        "maintainability": {"base": before, "head": after},
    }


def gate_markdown(result: dict[str, Any]) -> str:
    """Job-summary text for a gate result."""
    lines = ["## SecGuard pull-request gate", ""]
    lines.append("Passed: this change does not make the application worse." if result["passed"] else "Failed:")
    lines.extend(f"- {problem}" for problem in result["problems"])
    if result["new_findings"]:
        lines += ["", "| Severity | Rule | Finding | Location |", "| --- | --- | --- | --- |"]
        lines.extend(
            "| {severity} | {rule_id} | {title} | `{location}` |".format(
                **{key: str(finding.get(key) or "").replace("|", "\\|") for key in ("severity", "rule_id", "title", "location")}
            )
            for finding in result["new_findings"][:50]
        )
    rating = result["maintainability"]
    if rating["base"] is not None and rating["head"] is not None:
        lines += ["", f"Maintainability: {rating['base']:.1f} → {rating['head']:.1f} stars."]
    return "\n".join(lines) + "\n"
