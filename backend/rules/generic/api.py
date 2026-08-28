from __future__ import annotations

from typing import Any

from backend.rules.base import (
    API,
    Finding,
    Rule,
    ScanContext,
)

API_CONTENT_TYPES = (
    "application/json",
    "application/xml",
    "text/xml",
    "application/hal+json",
    "application/vnd.api+json",
    "application/atom+xml",
)

DOCUMENTATION_MARKERS = (
    "swagger",
    "openapi",
    "redoc",
    "\"paths\"",
    "api documentation",
)


def _accessible(entry: dict[str, Any]) -> bool:
    return entry.get("probed") and entry.get("state") == "accessible"


def _serves_api_content(entry: dict[str, Any]) -> bool:
    content_type = str(entry.get("content_type") or "").lower()

    return any(marker in content_type for marker in API_CONTENT_TYPES)


class ExposedApiDocumentation(Rule):
    id = "GEN-API-001"
    title = "API documentation is publicly reachable"
    severity = "medium"
    confidence = "confirmed"
    category = API
    cwe = "CWE-200"
    owasp = "A05:2021 Security Misconfiguration"
    recommendation = (
        "Restrict Swagger/OpenAPI documents to authenticated internal "
        "users, or disable them in production builds."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for entry in context.attack_surface.get(
            "potential_api_paths"
        ) or []:
            if not entry.get("documentation") or not _accessible(entry):
                continue

            body = str(entry.get("body_preview") or "").lower()

            markers = [
                marker
                for marker in DOCUMENTATION_MARKERS
                if marker in body
            ]

            if not markers and not _serves_api_content(entry):
                continue

            findings.append(
                self.finding(
                    context,
                    title=(
                        "API documentation is publicly reachable at "
                        f"{entry.get('path')}"
                    ),
                    location=str(entry.get("url") or context.final_url),
                    description=(
                        "The API specification is served without "
                        "authentication, giving an attacker a complete "
                        "map of the API — its endpoints, parameters and "
                        "data model."
                    ),
                    evidence={
                        "url": entry.get("url"),
                        "status_code": entry.get("status_code"),
                        "content_type": entry.get("content_type"),
                        "matched_markers": markers,
                    },
                )
            )

        return findings


class UnauthenticatedApiEndpoint(Rule):
    id = "GEN-API-002"
    title = "API endpoint responds without authentication"
    severity = "medium"
    confidence = "firm"
    category = API
    cwe = "CWE-306"
    owasp = "A01:2021 Broken Access Control"
    recommendation = (
        "Require authentication and authorization on API endpoints, and "
        "return 401 rather than data to anonymous callers."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for entry in context.attack_surface.get(
            "potential_api_paths"
        ) or []:
            if entry.get("documentation") or not _accessible(entry):
                continue

            if not _serves_api_content(entry):
                continue

            findings.append(
                self.finding(
                    context,
                    title=(
                        f"API endpoint {entry.get('path')} responds to "
                        "anonymous requests"
                    ),
                    location=str(entry.get("url") or context.final_url),
                    description=(
                        "An unauthenticated request to this endpoint "
                        "returned a successful API response. Confirm "
                        "whether the data it exposes is intended to be "
                        "public."
                    ),
                    evidence={
                        "url": entry.get("url"),
                        "status_code": entry.get("status_code"),
                        "content_type": entry.get("content_type"),
                        "content_length": entry.get("content_length"),
                        "body_preview": entry.get("body_preview", "")[:200],
                    },
                )
            )

        return findings


class ExposedGraphQlEndpoint(Rule):
    id = "GEN-API-003"
    title = "GraphQL endpoint is publicly reachable"
    severity = "medium"
    confidence = "firm"
    category = API
    cwe = "CWE-200"
    owasp = "A05:2021 Security Misconfiguration"
    recommendation = (
        "Require authentication on the GraphQL endpoint and disable "
        "introspection and any GraphQL IDE in production."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        for entry in context.attack_surface.get(
            "potential_api_paths"
        ) or []:
            if entry.get("path") not in ("/graphql",):
                continue

            if not _accessible(entry):
                continue

            body = str(entry.get("body_preview") or "").lower()

            introspection = "__schema" in body or "graphiql" in body

            return [
                self.finding(
                    context,
                    severity="high" if introspection else self.severity,
                    location=str(entry.get("url") or context.final_url),
                    description=(
                        "A GraphQL endpoint answered an anonymous request."
                        + (
                            " The response mentions introspection or an "
                            "in-browser IDE, which exposes the full schema."
                            if introspection
                            else ""
                        )
                    ),
                    evidence={
                        "url": entry.get("url"),
                        "status_code": entry.get("status_code"),
                        "introspection_indicators": introspection,
                    },
                )
            ]

        return []


def rules() -> list[Rule]:
    return [
        ExposedApiDocumentation(),
        UnauthenticatedApiEndpoint(),
        ExposedGraphQlEndpoint(),
    ]
