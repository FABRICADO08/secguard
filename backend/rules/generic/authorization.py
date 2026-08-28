from __future__ import annotations

from backend.rules.base import (
    AUTHORIZATION,
    INFORMATION_DISCLOSURE,
    Finding,
    Rule,
    ScanContext,
)

ADMIN_PATH_MARKERS = (
    "/admin",
    "/administrator",
    "/manage",
    "/management",
    "/console",
    "/dashboard",
    "/actuator",
    "/phpmyadmin",
    "/wp-admin",
)


class ExposedSensitivePath(Rule):
    id = "GEN-CFG-001"
    title = "Sensitive file is publicly accessible"
    severity = "high"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-538"
    owasp = "A05:2021 Security Misconfiguration"
    recommendation = (
        "Remove the file from the web root or block it at the web server, "
        "and rotate any credential it may have disclosed."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for exposure in context.attack_surface.get("exposed_paths") or []:
            findings.append(
                self.finding(
                    context,
                    title=(
                        f"{exposure.get('label')} is publicly accessible "
                        f"at {exposure.get('path')}"
                    ),
                    severity=exposure.get("severity", self.severity),
                    confidence=exposure.get("confidence", "tentative"),
                    location=str(exposure.get("url") or context.final_url),
                    description=(
                        f"An anonymous request to {exposure.get('path')} "
                        f"returned HTTP {exposure.get('status_code')} with "
                        "content that does not match the site's not-found "
                        "response."
                    ),
                    evidence=exposure,
                )
            )

        return findings


class UnauthenticatedAdministrativeInterface(Rule):
    id = "GEN-AUTHZ-001"
    title = "Administrative path is reachable from an anonymous crawl"
    severity = "medium"
    confidence = "tentative"
    category = AUTHORIZATION
    cwe = "CWE-306"
    owasp = "A01:2021 Broken Access Control"
    recommendation = (
        "Require authentication on administrative interfaces and restrict "
        "them to trusted networks."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        reachable = []

        for page in context.pages:
            url = str(page.get("url") or "").lower()

            status = page.get("status_code")

            if status is None or not 200 <= int(status) < 300:
                continue

            matched = [
                marker
                for marker in ADMIN_PATH_MARKERS
                if marker in url
            ]

            if matched:
                reachable.append(
                    {
                        "url": page.get("url"),
                        "status_code": status,
                        "matched": matched,
                    }
                )

        if not reachable:
            return []

        return [
            self.finding(
                context,
                location=str(reachable[0]["url"]),
                description=(
                    "The unauthenticated crawl reached pages whose paths "
                    "suggest an administrative interface. Verify that "
                    "these pages enforce authorization server side rather "
                    "than only hiding functionality in the UI."
                ),
                evidence={"pages": reachable[:20]},
            )
        ]


def rules() -> list[Rule]:
    return [
        ExposedSensitivePath(),
        UnauthenticatedAdministrativeInterface(),
    ]
