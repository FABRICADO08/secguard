"""Map repository-analysis results onto the normalized finding schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.repository.quality import Issue
from backend.risk.confidence import CONFIRMED, FIRM, TENTATIVE
from backend.rules.base import Finding

PLATFORM = "Repository"

SUPPLY_CHAIN = "supply-chain"
LICENSING = "licensing"
MAINTAINABILITY = "maintainability"

A06 = "A06:2021 Vulnerable and Outdated Components"
A08 = "A08:2021 Software and Data Integrity Failures"

RULE_CATALOGUE: dict[str, dict[str, str]] = {
    "REPO-DEP-001": {"title": "Dependency has a known vulnerability", "category": SUPPLY_CHAIN, "cwe": "CWE-1395", "owasp": A06},
    "REPO-DEP-002": {"title": "Dependency is deprecated", "category": SUPPLY_CHAIN, "cwe": "CWE-1104", "owasp": A06},
    "REPO-DEP-003": {"title": "Dependency appears unmaintained", "category": SUPPLY_CHAIN, "cwe": "CWE-1104", "owasp": A06},
    "REPO-DEP-004": {"title": "Dependency's upstream repository is archived", "category": SUPPLY_CHAIN, "cwe": "CWE-1104", "owasp": A06},
    "REPO-DEP-005": {"title": "Dependency is major versions behind", "category": SUPPLY_CHAIN, "cwe": "CWE-1104", "owasp": A06},
    "REPO-DEP-006": {"title": "Dependency version is not pinned", "category": SUPPLY_CHAIN, "cwe": "CWE-1357", "owasp": A08},
    "REPO-DEP-007": {"title": "Dependency has a single maintainer", "category": SUPPLY_CHAIN, "cwe": "CWE-1357", "owasp": A08},
    "REPO-SUP-001": {"title": "Possible typo-squatted package", "category": SUPPLY_CHAIN, "cwe": "CWE-506", "owasp": A08},
    "REPO-SUP-002": {"title": "Newly published, rarely used package", "category": SUPPLY_CHAIN, "cwe": "CWE-1357", "owasp": A08},
    "REPO-LIC-001": {"title": "Strong copyleft licence", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-LIC-002": {"title": "Network copyleft licence", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-LIC-003": {"title": "Non-commercial or source-available licence", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-LIC-004": {"title": "Licence is missing or unrecognised", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-LIC-005": {"title": "Dual-licence trap", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-LIC-006": {"title": "Weak copyleft licence", "category": LICENSING, "cwe": "", "owasp": ""},
    "REPO-MNT-001": {"title": "Function is too complex", "category": MAINTAINABILITY, "cwe": "CWE-1121", "owasp": ""},
    "REPO-MNT-002": {"title": "Function is too long", "category": MAINTAINABILITY, "cwe": "CWE-1080", "owasp": ""},
    "REPO-MNT-003": {"title": "Function has too many parameters", "category": MAINTAINABILITY, "cwe": "CWE-1064", "owasp": ""},
    "REPO-MNT-004": {"title": "Class or file is oversized", "category": MAINTAINABILITY, "cwe": "CWE-1080", "owasp": ""},
    "REPO-MNT-005": {"title": "Unused import", "category": MAINTAINABILITY, "cwe": "CWE-1164", "owasp": ""},
    "REPO-MNT-006": {"title": "Unused local variable", "category": MAINTAINABILITY, "cwe": "CWE-563", "owasp": ""},
    "REPO-MNT-007": {"title": "Unreachable code", "category": MAINTAINABILITY, "cwe": "CWE-561", "owasp": ""},
    "REPO-MNT-008": {"title": "Duplicated code block", "category": MAINTAINABILITY, "cwe": "CWE-1041", "owasp": ""},
    "REPO-MNT-009": {"title": "Low docstring coverage", "category": MAINTAINABILITY, "cwe": "CWE-1116", "owasp": ""},
    "REPO-MNT-010": {"title": "Low type-annotation coverage", "category": MAINTAINABILITY, "cwe": "", "owasp": ""},
    "REPO-MNT-011": {"title": "Repository has no README", "category": MAINTAINABILITY, "cwe": "CWE-1059", "owasp": ""},
    "REPO-MNT-013": {"title": "HTTP API has no specification", "category": MAINTAINABILITY, "cwe": "CWE-1059", "owasp": ""},
}

QUALITY_RECOMMENDATIONS = {
    "REPO-MNT-001": "Split the function into smaller functions with one responsibility each; replace nested conditionals with early returns or lookup tables.",
    "REPO-MNT-002": "Extract cohesive steps into well-named helper functions so each unit fits on one screen.",
    "REPO-MNT-003": "Group related parameters into a data class or options object.",
    "REPO-MNT-004": "Split the class or file along its responsibilities into smaller modules.",
    "REPO-MNT-005": "Remove the unused import.",
    "REPO-MNT-006": "Remove the variable, or use `_` if the value is intentionally discarded.",
    "REPO-MNT-007": "Delete the unreachable statements or fix the control flow that skips them.",
    "REPO-MNT-008": "Extract the duplicated logic into a shared function and call it from both places.",
    "REPO-MNT-009": "Document public modules, classes and functions with docstrings describing purpose and contract.",
    "REPO-MNT-010": "Add parameter and return type annotations to public functions and run a type checker in CI.",
    "REPO-MNT-011": "Add a README describing purpose, setup, configuration and how to run tests.",
    "REPO-MNT-013": "Publish an OpenAPI specification for the HTTP API and keep it in the repository.",
}

QUALITY_SEVERITY = {
    "REPO-MNT-001": "medium", "REPO-MNT-002": "low", "REPO-MNT-003": "low", "REPO-MNT-004": "low",
    "REPO-MNT-005": "informational", "REPO-MNT-006": "low", "REPO-MNT-007": "low", "REPO-MNT-008": "low",
    "REPO-MNT-009": "low", "REPO-MNT-010": "low", "REPO-MNT-011": "low", "REPO-MNT-013": "low",
}


@dataclass
class FindingOptions:
    confidence: str = FIRM
    title: str = ""
    references: list[str] | None = None


def make_finding(
    rule_id: str,
    severity: str,
    description: str,
    recommendation: str,
    location: str,
    evidence: dict[str, Any],
    **overrides: Any,
) -> dict[str, Any]:
    options = FindingOptions(**overrides)
    metadata = RULE_CATALOGUE[rule_id]

    return Finding(
        rule_id=rule_id,
        title=options.title or metadata["title"],
        severity=severity,
        category=metadata["category"],
        description=description,
        recommendation=recommendation,
        confidence=options.confidence,
        platform=PLATFORM,
        location=location,
        cwe=metadata["cwe"],
        owasp=metadata["owasp"],
        references=options.references or [],
        evidence=evidence,
    ).to_dict()


def quality_finding(issue: Issue) -> dict[str, Any]:
    location = f"{issue.path}:{issue.line}" if issue.path and issue.line else issue.path or "repository"

    severity = QUALITY_SEVERITY.get(issue.rule_id, "low")

    if issue.rule_id == "REPO-MNT-001" and (issue.metric or 0) > 20:
        severity = "high"

    return make_finding(
        issue.rule_id,
        severity,
        issue.message,
        QUALITY_RECOMMENDATIONS.get(issue.rule_id, ""),
        location,
        {key: value for key, value in issue.to_dict().items() if value not in (None, "", 0)},
        confidence=CONFIRMED,
        title=f"{RULE_CATALOGUE[issue.rule_id]['title']}: {issue.symbol}" if issue.symbol else "",
    )


__all__ = [
    "CONFIRMED",
    "FIRM",
    "LICENSING",
    "MAINTAINABILITY",
    "PLATFORM",
    "RULE_CATALOGUE",
    "SUPPLY_CHAIN",
    "TENTATIVE",
    "make_finding",
    "quality_finding",
]
