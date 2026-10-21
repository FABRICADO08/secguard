"""Map repository-analysis results onto the normalized finding schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.platforms.mendix import findings as mendix_rules
from backend.repository.code_issues import SecurityIssue
from backend.repository.quality import Issue
from backend.risk.confidence import CONFIRMED, FIRM, TENTATIVE
from backend.rules.base import Finding

PLATFORM = "Repository"

SUPPLY_CHAIN = "supply-chain"
LICENSING = "licensing"
MAINTAINABILITY = "maintainability"
INPUT_VALIDATION = "input-validation"
INFORMATION_DISCLOSURE = "information-disclosure"
TRANSPORT = "transport"
CONFIGURATION = "configuration"

A06 = "A06:2021 Vulnerable and Outdated Components"
A08 = "A08:2021 Software and Data Integrity Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"
A07 = "A07:2021 Identification and Authentication Failures"
A02 = "A02:2021 Cryptographic Failures"
A01 = "A01:2021 Broken Access Control"

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
    "REPO-SEC-001": {"title": "SQL injection", "category": INPUT_VALIDATION, "cwe": "CWE-89", "owasp": A03},
    "REPO-SEC-002": {"title": "OS command injection", "category": INPUT_VALIDATION, "cwe": "CWE-78", "owasp": A03},
    "REPO-SEC-003": {"title": "Code injection", "category": INPUT_VALIDATION, "cwe": "CWE-95", "owasp": A03},
    "REPO-SEC-004": {"title": "Unsafe deserialization", "category": INPUT_VALIDATION, "cwe": "CWE-502", "owasp": A08},
    "REPO-SEC-005": {"title": "Hard-coded secret", "category": INFORMATION_DISCLOSURE, "cwe": "CWE-798", "owasp": A07},
    "REPO-SEC-006": {"title": "Secret in git history", "category": INFORMATION_DISCLOSURE, "cwe": "CWE-798", "owasp": A07},
    "REPO-SEC-007": {"title": "TLS certificate validation disabled", "category": TRANSPORT, "cwe": "CWE-295", "owasp": A07},
    "REPO-SEC-008": {"title": "Debug mode enabled", "category": CONFIGURATION, "cwe": "CWE-489", "owasp": A05},
    "REPO-IAC-001": {"title": "Container runs as root", "category": CONFIGURATION, "cwe": "CWE-250", "owasp": A05},
    "REPO-IAC-002": {"title": "Container base image is not pinned", "category": SUPPLY_CHAIN, "cwe": "CWE-1357", "owasp": A08},
    "REPO-IAC-003": {"title": "Secret baked into container image", "category": INFORMATION_DISCLOSURE, "cwe": "CWE-798", "owasp": A07},
    "REPO-IAC-004": {"title": "Remote file used without integrity check", "category": SUPPLY_CHAIN, "cwe": "CWE-494", "owasp": A08},
    "REPO-IAC-005": {"title": "Workload has host-level privileges", "category": CONFIGURATION, "cwe": "CWE-250", "owasp": A05},
    "REPO-IAC-006": {"title": "Workload may run as root", "category": CONFIGURATION, "cwe": "CWE-250", "owasp": A05},
    "REPO-IAC-007": {"title": "Workload has no resource limits", "category": CONFIGURATION, "cwe": "CWE-770", "owasp": A05},
    "REPO-IAC-008": {"title": "Storage is publicly accessible", "category": CONFIGURATION, "cwe": "CWE-732", "owasp": A01},
    "REPO-IAC-009": {"title": "Admin port open to the internet", "category": CONFIGURATION, "cwe": "CWE-284", "owasp": A05},
    "REPO-IAC-010": {"title": "Database is publicly accessible", "category": CONFIGURATION, "cwe": "CWE-284", "owasp": A05},
    "REPO-IAC-011": {"title": "Encryption at rest disabled", "category": CONFIGURATION, "cwe": "CWE-311", "owasp": A02},
    "REPO-IAC-012": {"title": "Workflow token permissions are not restricted", "category": CONFIGURATION, "cwe": "CWE-272", "owasp": A05},
    "REPO-IAC-013": {"title": "Workflow runs untrusted pull-request code with secrets", "category": CONFIGURATION, "cwe": "CWE-829", "owasp": A08},
    "REPO-IAC-014": {"title": "Script injection in workflow", "category": INPUT_VALIDATION, "cwe": "CWE-78", "owasp": A03},
    "REPO-IAC-015": {"title": "Third-party action is not pinned to a commit", "category": SUPPLY_CHAIN, "cwe": "CWE-829", "owasp": A08},
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

CODE_SECURITY_RECOMMENDATIONS = {
    "REPO-IAC-001": "Create an unprivileged user in the image and switch to it with `USER` in the final stage.",
    "REPO-IAC-002": "Pin the base image to a specific version tag, ideally with its `@sha256:` digest, and update it deliberately.",
    "REPO-IAC-003": "Remove the value from the Dockerfile, rotate it, and pass it at runtime or with a BuildKit `--secret` mount.",
    "REPO-IAC-004": "Download to a file, verify a published checksum or signature, then run it; give `ADD` a `--checksum`.",
    "REPO-IAC-005": "Remove privileged mode, host namespaces and hostPath volumes, and set `allowPrivilegeEscalation: false`.",
    "REPO-IAC-006": "Set `runAsNonRoot: true` and a non-zero `runAsUser` in the pod or container `securityContext`.",
    "REPO-IAC-007": "Set CPU and memory `resources.limits` (and requests) for every container.",
    "REPO-IAC-008": "Keep storage private, enable every public access block setting, and share data through signed URLs or identities.",
    "REPO-IAC-009": "Restrict SSH/RDP to known address ranges or a bastion/VPN, or use a managed session service instead.",
    "REPO-IAC-010": "Set `publicly_accessible = false` and reach the database from private networks only.",
    "REPO-IAC-011": "Turn encryption at rest on, preferably with a customer-managed key.",
    "REPO-IAC-012": "Add a top-level `permissions:` block granting only what the jobs need, e.g. `contents: read`.",
    "REPO-IAC-013": "Use `pull_request` for untrusted code, or keep `pull_request_target` jobs from checking out and running the PR's code.",
    "REPO-IAC-014": "Pass the value through an `env:` variable and quote it in the script (`\"$TITLE\"`) instead of `${{ }}` interpolation.",
    "REPO-IAC-015": "Pin the action to a full commit SHA (with the version in a comment) and let Dependabot update it.",
    "REPO-SEC-001": "Use parameterized queries or the ORM's query builder; never put untrusted values into the SQL text.",
    "REPO-SEC-002": "Pass the command as an argument list without a shell, and validate any user-controlled argument against an allow-list.",
    "REPO-SEC-003": "Remove dynamic code evaluation; parse data with a safe parser such as JSON, or dispatch through a fixed lookup table.",
    "REPO-SEC-004": "Deserialize untrusted data only with data-only formats (JSON, yaml.safe_load) or a type allow-list.",
    "REPO-SEC-005": "Revoke and rotate the secret, then load it from the environment or a secrets manager instead of the source.",
    "REPO-SEC-006": "Revoke and rotate the secret: removing it from the code does not remove it from git history. Rewrite history only after rotating.",
    "REPO-SEC-007": "Keep certificate validation on; trust a private CA by adding it to the trust store instead of disabling verification.",
    "REPO-SEC-008": "Turn debug mode off in deployed configuration and drive it from an environment variable that defaults to off.",
}

CODE_SECURITY_SEVERITY = {
    "REPO-IAC-001": "medium", "REPO-IAC-002": "low", "REPO-IAC-003": "high", "REPO-IAC-004": "medium",
    "REPO-IAC-005": "high", "REPO-IAC-006": "medium", "REPO-IAC-007": "low", "REPO-IAC-008": "high",
    "REPO-IAC-009": "high", "REPO-IAC-010": "high", "REPO-IAC-011": "medium", "REPO-IAC-012": "medium",
    "REPO-IAC-013": "high", "REPO-IAC-014": "high", "REPO-IAC-015": "low",
    "REPO-SEC-001": "high", "REPO-SEC-002": "high", "REPO-SEC-003": "high", "REPO-SEC-004": "high",
    "REPO-SEC-005": "high", "REPO-SEC-006": "high", "REPO-SEC-007": "medium", "REPO-SEC-008": "medium",
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


MENDIX_RULE_IDS = frozenset({*mendix_rules.RULE_CATALOGUE, mendix_rules.CATALOGUE.default_rule_id})


def rule_metadata(rule_id: Any) -> dict[str, str] | None:
    """Catalogue entry and platform for a rule a repository report may carry."""

    if rule_id in RULE_CATALOGUE:
        return {**RULE_CATALOGUE[rule_id], "platform": PLATFORM}

    if rule_id in MENDIX_RULE_IDS:
        metadata = mendix_rules.RULE_CATALOGUE.get(rule_id, mendix_rules.DEFAULT_METADATA)
        return {**metadata, "platform": mendix_rules.PLATFORM}

    return None


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



def code_security_finding(issue: SecurityIssue) -> dict[str, Any]:
    location = f"{issue.path}:{issue.line}" if issue.line else issue.path
    evidence = {"snippet": issue.snippet, **issue.details} if issue.snippet else dict(issue.details)
    return make_finding(
        issue.rule_id,
        CODE_SECURITY_SEVERITY[issue.rule_id],
        issue.message,
        CODE_SECURITY_RECOMMENDATIONS[issue.rule_id],
        location,
        evidence,
        confidence=issue.confidence,
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
    "code_security_finding",
    "make_finding",
    "quality_finding",
    "rule_metadata",
]
