from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.rules.base import Finding


def build_finding(
    raw: dict[str, Any],
    rule_id: str,
    metadata: dict[str, str],
    platform: str,
    location: str,
    evidence: dict[str, Any],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=str(raw.get("title") or metadata["title"]),
        severity=str(raw.get("severity") or "medium"),
        category=metadata["category"],
        description=str(raw.get("risk") or ""),
        recommendation=str(raw.get("recommendation") or ""),
        confidence=metadata["confidence"],
        platform=platform,
        location=location,
        cwe=metadata["cwe"],
        owasp=metadata["owasp"],
        evidence=evidence,
    )


def normalize_findings(
    raw_findings: list[dict[str, Any]],
    to_finding: Callable[[dict[str, Any]], Finding],
) -> list[dict[str, Any]]:
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
