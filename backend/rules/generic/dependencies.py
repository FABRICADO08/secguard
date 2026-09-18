from __future__ import annotations

from typing import Any

from backend.knowledge.advisories import (
    advisories_for,
    end_of_life_for,
)
from backend.rules.base import (
    CONFIGURATION,
    Finding,
    Rule,
    ScanContext,
)

# The worst advisory severity decides the finding severity, so one
# critical issue is not diluted by several minor ones.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

def libraries(context: ScanContext) -> list[dict[str, Any]]:
    return [
        entry
        for entry in (context.attack_surface.get("libraries") or [])
        if isinstance(entry, dict) and entry.get("version")
    ]


def _worst(severities: list[str]) -> str:
    ranked = sorted(
        severities,
        key=lambda value: SEVERITY_ORDER.index(value)
        if value in SEVERITY_ORDER
        else 0,
    )

    return ranked[-1] if ranked else "medium"


class VulnerableComponent(Rule):
    id = "GEN-DEP-001"
    title = "Component version has known vulnerabilities"
    severity = "high"
    confidence = "firm"
    category = CONFIGURATION
    cwe = "CWE-1395"
    owasp = "A06:2021 Vulnerable and Outdated Components"
    description = (
        "The target discloses a component version that public advisories "
        "list as vulnerable. Whether the vulnerable code path is reachable "
        "depends on how the component is used, but the version itself is "
        "already known-bad."
    )
    recommendation = (
        "Upgrade the component to a release at or above the fixed version "
        "named in the advisory, then re-scan to confirm the banner and "
        "bundled filename changed."
    )
    references = (
        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for entry in libraries(context):
            name = str(entry["name"])
            version = str(entry["version"])

            matches = advisories_for(name, version)

            if not matches:
                continue

            findings.append(
                self.finding(
                    context,
                    title=f"{name} {version} has known vulnerabilities",
                    severity=_worst([item.severity for item in matches]),
                    location=str(entry.get("evidence") or ""),
                    evidence={
                        "component": name,
                        "version": version,
                        "source": entry.get("source", ""),
                        "advisories": [
                            {
                                "id": item.identifier,
                                "severity": item.severity,
                                "summary": item.summary,
                                "fixed_in": item.fixed_in,
                            }
                            for item in matches
                        ],
                    },
                )
            )

        return findings


class UnsupportedComponent(Rule):
    id = "GEN-DEP-002"
    title = "Component release line is no longer supported"
    severity = "medium"
    confidence = "firm"
    category = CONFIGURATION
    cwe = "CWE-1104"
    owasp = "A06:2021 Vulnerable and Outdated Components"
    description = (
        "The detected release line receives no security fixes, so any "
        "vulnerability found in it from now on stays unpatched."
    )
    recommendation = (
        "Plan a migration to a supported major version; a component that "
        "is merely current today still becomes unfixable once its branch "
        "is retired."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for entry in libraries(context):
            name = str(entry["name"])
            version = str(entry["version"])

            unsupported = end_of_life_for(name, version)

            if unsupported is None:
                continue

            findings.append(
                self.finding(
                    context,
                    title=f"{name} {version} is no longer supported",
                    location=str(entry.get("evidence") or ""),
                    evidence={
                        "component": name,
                        "version": version,
                        "source": entry.get("source", ""),
                        "note": unsupported.note,
                    },
                )
            )

        return findings


def rules() -> list[Rule]:
    return [
        VulnerableComponent(),
        UnsupportedComponent(),
    ]
