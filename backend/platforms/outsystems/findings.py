from __future__ import annotations

from typing import Any

from backend.risk.confidence import CONFIRMED, FIRM
from backend.rules.base import (
    AUTHENTICATION,
    AUTHORIZATION,
    CONFIGURATION,
    INFORMATION_DISCLOSURE,
    INPUT_VALIDATION,
    TRANSPORT,
    Finding,
)
from backend.platforms.finding_utils import (
    build_finding,
    normalize_findings,
)

PLATFORM = "OutSystems"


# Metadata the analyzer does not carry: category, weakness references
# and how much the model tells us about real exploitability.
RULE_CATALOGUE: dict[str, dict[str, str]] = {
    "OSSEC-101": {
        "title": "Screen is reachable without a role",
        "category": AUTHORIZATION,
        "confidence": CONFIRMED,
        "cwe": "CWE-306",
        "owasp": "A01:2021 Broken Access Control",
    },
    "OSSEC-102": {
        "title": "Exposed REST method requires no authentication",
        "category": AUTHENTICATION,
        "confidence": CONFIRMED,
        "cwe": "CWE-306",
        "owasp": "A07:2021 Identification and Authentication Failures",
    },
    "OSSEC-103": {
        "title": "Public entity allows writes from consuming modules",
        "category": AUTHORIZATION,
        "confidence": FIRM,
        "cwe": "CWE-284",
        "owasp": "A01:2021 Broken Access Control",
    },
    "OSSEC-104": {
        "title": "Site property ships a secret as its default value",
        "category": INFORMATION_DISCLOSURE,
        "confidence": CONFIRMED,
        "cwe": "CWE-798",
        "owasp": "A07:2021 Identification and Authentication Failures",
    },
    "OSSEC-105": {
        "title": "Sensitive attribute is stored unencrypted",
        "category": INFORMATION_DISCLOSURE,
        "confidence": FIRM,
        "cwe": "CWE-311",
        "owasp": "A02:2021 Cryptographic Failures",
    },
    "OSSEC-106": {
        "title": "Advanced SQL expands a parameter inline",
        "category": INPUT_VALIDATION,
        "confidence": FIRM,
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
    },
    "OSSEC-107": {
        "title": "Consumed API is called over plain HTTP",
        "category": TRANSPORT,
        "confidence": CONFIRMED,
        "cwe": "CWE-319",
        "owasp": "A02:2021 Cryptographic Failures",
    },
}


DEFAULT_METADATA: dict[str, str] = {
    "title": "OutSystems model security finding",
    "category": CONFIGURATION,
    "confidence": FIRM,
    "cwe": "",
    "owasp": "A04:2021 Insecure Design",
}


def _evidence(raw: dict[str, Any]) -> dict[str, Any]:
    evidence = dict(raw.get("evidence") or {})

    module = raw.get("module")

    if module:
        evidence.setdefault("module", module)

    return evidence


def to_finding(raw: dict[str, Any]) -> Finding:
    """Map one analyzer result onto the normalized finding schema."""

    rule_id = str(raw.get("rule_id") or "OSSEC-000")

    metadata = RULE_CATALOGUE.get(rule_id, DEFAULT_METADATA)

    return build_finding(
        raw,
        rule_id,
        metadata,
        PLATFORM,
        str(raw.get("location") or ""),
        _evidence(raw),
    )


def to_findings(
    raw_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize analyzer output, worst findings first."""

    return normalize_findings(
        raw_findings,
        to_finding,
    )


__all__ = [
    "PLATFORM",
    "RULE_CATALOGUE",
    "to_finding",
    "to_findings",
]
