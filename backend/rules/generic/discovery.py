from __future__ import annotations

from typing import Any

from backend.rules.base import (
    INFORMATION_DISCLOSURE,
    INPUT_VALIDATION,
    Finding,
    Rule,
    ScanContext,
)


def _robots(context: ScanContext) -> dict[str, Any]:
    section = context.attack_surface.get("robots")

    return section if isinstance(section, dict) else {}


def _script_analysis(context: ScanContext) -> list[dict[str, Any]]:
    section = context.attack_surface.get("script_analysis")

    if not isinstance(section, dict):
        return []

    return [entry for entry in section.get("scripts") or [] if isinstance(entry, dict)]


def _reflection(context: ScanContext) -> list[dict[str, Any]]:
    section = context.attack_surface.get("reflection")

    if not isinstance(section, dict):
        return []

    return [entry for entry in section.get("reflected") or [] if isinstance(entry, dict)]


class RobotsRevealsSensitivePaths(Rule):
    id = "GEN-INF-004"
    title = "robots.txt discloses sensitive paths"
    severity = "low"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-200"
    owasp = "A01:2021 Broken Access Control"
    description = (
        "robots.txt disallows paths whose names suggest administrative or "
        "internal functionality. The file is public, so listing them there "
        "advertises exactly the areas an attacker would look for."
    )
    recommendation = (
        "Do not rely on robots.txt to hide anything. Protect these paths "
        "with authentication and authorization, and exclude them from "
        "indexing with `X-Robots-Tag` or `noindex` instead of naming them."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        robots = _robots(context)

        sensitive = [
            path
            for path in robots.get("sensitive_disallowed") or []
            if isinstance(path, str)
        ]

        if not sensitive:
            return []

        return [
            self.finding(
                context,
                location=str(robots.get("url") or context.final_url),
                evidence={"paths": sensitive[:20]},
            )
        ]


class ScriptFileSecret(Rule):
    id = "GEN-JS-003"
    title = "Secret material is embedded in a JavaScript file"
    severity = "high"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-798"
    owasp = "A07:2021 Identification and Authentication Failures"
    description = (
        "A script served by the application contains what looks like a "
        "credential. Bundlers routinely inline environment variables, so a "
        "server-side key can end up shipped to every visitor."
    )
    recommendation = (
        "Revoke the exposed value and keep it out of the client bundle: "
        "only variables that are safe to publish belong in front-end "
        "configuration."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for script in _script_analysis(context):
            for secret in script.get("secrets") or []:
                if not isinstance(secret, dict):
                    continue

                kind = str(secret.get("kind") or "Secret")

                findings.append(
                    self.finding(
                        context,
                        title=f"{kind} is embedded in a JavaScript file",
                        location=str(script.get("url") or context.final_url),
                        evidence={
                            "kind": kind,
                            "match": str(secret.get("match") or ""),
                            "script": str(script.get("url") or ""),
                        },
                    )
                )

        return findings


class ScriptSourceMapExposed(Rule):
    id = "GEN-JS-004"
    title = "JavaScript bundle ships a source map reference"
    severity = "low"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-540"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "A served script ends with a sourceMappingURL comment. If the map "
        "is deployed alongside it, the original source, comments and "
        "internal paths are readable by anyone."
    )
    recommendation = (
        "Build production bundles without source maps, or upload them to "
        "your error tracker instead of serving them."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for script in _script_analysis(context):
            maps = [item for item in script.get("source_maps") or [] if item]

            if not maps:
                continue

            findings.append(
                self.finding(
                    context,
                    location=str(script.get("url") or context.final_url),
                    evidence={"source_maps": maps},
                )
            )

        return findings


class ReflectedInput(Rule):
    id = "GEN-INP-001"
    title = "Request parameter is reflected unescaped"
    severity = "medium"
    confidence = "tentative"
    category = INPUT_VALIDATION
    cwe = "CWE-79"
    owasp = "A03:2021 Injection"
    description = (
        "An inert marker containing quotes and angle brackets was sent "
        "through this parameter and came back in the response with those "
        "characters intact. That is the precondition for reflected "
        "cross-site scripting; whether it is exploitable depends on where "
        "in the document the value lands."
    )
    recommendation = (
        "Escape the value for the context it is rendered into (HTML text, "
        "attribute, JavaScript or URL) rather than filtering the input, "
        "and add a Content-Security-Policy that forbids inline script."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for probe in _reflection(context):
            if probe.get("context") != "raw":
                continue

            parameter = str(probe.get("parameter") or "")

            findings.append(
                self.finding(
                    context,
                    title=f"Parameter '{parameter}' is reflected unescaped",
                    location=str(probe.get("url") or context.final_url),
                    evidence={
                        "parameter": parameter,
                        "source": str(probe.get("source") or ""),
                        "status_code": probe.get("status_code"),
                    },
                )
            )

        return findings


def rules() -> list[Rule]:
    return [
        RobotsRevealsSensitivePaths(),
        ScriptFileSecret(),
        ScriptSourceMapExposed(),
        ReflectedInput(),
    ]
