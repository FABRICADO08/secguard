from __future__ import annotations

from typing import Any

from backend.risk.confidence import CONFIRMED, FIRM
from backend.rules.base import (
    AUTHORIZATION,
    CONFIGURATION,
    INFORMATION_DISCLOSURE,
    Finding,
)

PLATFORM = "Mendix"


# Metadata the analyzer does not carry: category, weakness references
# and how much the model tells us about real exploitability.
RULE_CATALOGUE: dict[str, dict[str, str]] = {
    "MXSEC-101": {
        "title": "Entity access rule grants broad write access",
        "category": AUTHORIZATION,
        "confidence": CONFIRMED,
        "cwe": "CWE-284",
        "owasp": "A01:2021 Broken Access Control",
    },
    "MXSEC-102": {
        "title": "Sensitive entity has no explicit access rules",
        "category": AUTHORIZATION,
        "confidence": CONFIRMED,
        "cwe": "CWE-1220",
        "owasp": "A01:2021 Broken Access Control",
    },
    "MXSEC-106": {
        "title": "Sensitive attribute is accessible to application roles",
        "category": INFORMATION_DISCLOSURE,
        "confidence": FIRM,
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control",
    },
    "MXSEC-401": {
        "title": "Association has cascading delete behaviour",
        "category": CONFIGURATION,
        "confidence": FIRM,
        "cwe": "CWE-284",
        "owasp": "A04:2021 Insecure Design",
    },
}


DEFAULT_METADATA: dict[str, str] = {
    "title": "Mendix model security finding",
    "category": CONFIGURATION,
    "confidence": FIRM,
    "cwe": "",
    "owasp": "A04:2021 Insecure Design",
}


def _location(raw: dict[str, Any]) -> str:
    return str(
        raw.get("entity")
        or raw.get("association")
        or raw.get("module")
        or ""
    )


def _evidence(raw: dict[str, Any]) -> dict[str, Any]:
    evidence = dict(raw.get("evidence") or {})

    for key in (
        "module",
        "roles",
        "access",
        "xpath",
        "attributes",
        "sensitive",
        "sensitive_categories",
    ):
        value = raw.get(key)

        if value not in (None, "", [], {}):
            evidence.setdefault(key, value)

    return evidence


def to_finding(raw: dict[str, Any]) -> Finding:
    """Map one analyzer result onto the normalized finding schema."""

    rule_id = str(raw.get("rule_id") or "MXSEC-000")

    metadata = RULE_CATALOGUE.get(rule_id, DEFAULT_METADATA)

    return Finding(
        rule_id=rule_id,
        title=str(raw.get("title") or metadata["title"]),
        severity=str(raw.get("severity") or "medium"),
        category=metadata["category"],
        description=str(raw.get("risk") or ""),
        recommendation=str(raw.get("recommendation") or ""),
        confidence=metadata["confidence"],
        platform=PLATFORM,
        location=_location(raw),
        cwe=metadata["cwe"],
        owasp=metadata["owasp"],
        evidence=_evidence(raw),
    )


def to_findings(
    raw_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize analyzer output, worst findings first."""

    findings = [
        to_finding(raw).to_dict()
        for raw in raw_findings
        if isinstance(raw, dict)
    ]

    return sorted(
        findings,
        key=lambda finding: -int(
            (finding.get("risk") or {}).get("score") or 0
        ),
    )


__all__ = [
    "PLATFORM",
    "RULE_CATALOGUE",
    "to_finding",
    "to_findings",
]
