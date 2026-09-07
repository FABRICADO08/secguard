from __future__ import annotations

import re
from typing import Any

from backend.platforms.outsystems.model import (
    Attribute,
    ConsumedApi,
    Entity,
    OutSystemsModel,
    Query,
    RestMethod,
    Screen,
    SiteProperty,
)

# Authentication values that leave an exposed method open to anyone.
OPEN_AUTHENTICATION = frozenset({"", "none", "anonymous", "public"})

SECRET_PATTERNS = (
    r"password",
    r"passwd",
    r"secret",
    r"credential",
    r"api.?key",
    r"access.?key",
    r"private.?key",
    r"token",
    r"connection.?string",
)

PERSONAL_PATTERNS = (
    r"e.?mail",
    r"phone",
    r"mobile",
    r"address",
    r"date.?of.?birth",
    r"\bdob\b",
    r"national.?id",
    r"id.?number",
    r"passport",
    r"tax.?number",
    r"credit.?card",
    r"card.?number",
    r"bank.?account",
    r"account.?number",
    r"iban",
    r"salary",
)


def _matches(value: str, patterns: tuple[str, ...]) -> str:
    """Return the pattern a name matches, or an empty string."""

    normalized = re.sub(r"[\s\-_]+", "", str(value or "").lower())

    for pattern in patterns:

        if re.search(pattern, normalized, re.IGNORECASE):
            return pattern

    return ""


class OutSystemsSecurityAnalyzer:
    """
    Evaluates the parsed OutSystems model against the platform rules.

    Each rule returns raw dictionaries; `findings.to_findings` maps them
    onto the normalized schema shared with the generic scanner.
    """

    def __init__(self, model: OutSystemsModel) -> None:
        self.model = model

    def analyze(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for screen in self.model.screens:
            findings.extend(self._screen(screen))

        for method in self.model.rest_methods:
            findings.extend(self._rest_method(method))

        for entity in self.model.entities:
            findings.extend(self._entity(entity))

            for attribute in entity.attributes:
                findings.extend(self._attribute(entity, attribute))

        for site_property in self.model.site_properties:
            findings.extend(self._site_property(site_property))

        for query in self.model.queries:
            findings.extend(self._query(query))

        for api in self.model.consumed_apis:
            findings.extend(self._consumed_api(api))

        return findings

    # --------------------------------------------------------
    # Rules
    # --------------------------------------------------------

    def _screen(self, screen: Screen) -> list[dict[str, Any]]:
        if screen.roles and not screen.is_anonymous:
            return []

        return [
            {
                "rule_id": "OSSEC-101",
                "severity": "high",
                "location": screen.qualified_name,
                "module": screen.module,
                "risk":
                    f"Screen '{screen.qualified_name}' has no role "
                    "assigned, so it is reachable without signing in "
                    "and every action and data source on it runs "
                    "unauthenticated.",
                "recommendation":
                    "Assign the roles allowed to open this screen, or "
                    "keep it anonymous deliberately and move the data "
                    "it reads behind a protected server action.",
                "evidence": {
                    "anonymous": screen.is_anonymous,
                    "roles": screen.roles,
                },
            }
        ]

    def _rest_method(self, method: RestMethod) -> list[dict[str, Any]]:
        authentication = method.authentication.strip().lower()

        if authentication not in OPEN_AUTHENTICATION or method.roles:
            return []

        return [
            {
                "rule_id": "OSSEC-102",
                "severity": "critical",
                "location": method.qualified_name,
                "module": method.module,
                "risk":
                    f"Exposed REST method '{method.qualified_name}' "
                    "requires no authentication, so anyone who can "
                    "reach the environment can call it directly, "
                    "bypassing the screens that normally guard it.",
                "recommendation":
                    "Set the API or method to use basic, token or "
                    "custom authentication and check the caller's "
                    "roles in OnAuthentication.",
                "evidence": {
                    "http_method": method.http_method,
                    "authentication": method.authentication,
                    "roles": method.roles,
                },
            }
        ]

    def _entity(self, entity: Entity) -> list[dict[str, Any]]:
        if not entity.is_public or entity.expose_read_only:
            return []

        return [
            {
                "rule_id": "OSSEC-103",
                "severity": "medium",
                "location": entity.qualified_name,
                "module": entity.module,
                "risk":
                    f"Entity '{entity.qualified_name}' is public with "
                    "write access, so any consuming module can create, "
                    "update and delete its records without going "
                    "through this module's validation.",
                "recommendation":
                    "Set 'Expose Read Only' on the entity and publish "
                    "server actions for the writes consumers need, so "
                    "the owning module keeps its invariants.",
                "evidence": {
                    "public": entity.is_public,
                    "expose_read_only": entity.expose_read_only,
                },
            }
        ]

    def _attribute(
        self,
        entity: Entity,
        attribute: Attribute,
    ) -> list[dict[str, Any]]:
        if attribute.is_encrypted:
            return []

        secret = _matches(attribute.name, SECRET_PATTERNS)
        personal = _matches(attribute.name, PERSONAL_PATTERNS)

        if not secret and not personal:
            return []

        return [
            {
                "rule_id": "OSSEC-105",
                "severity": "high" if secret else "medium",
                "location": attribute.qualified_name,
                "module": entity.module,
                "risk":
                    f"Attribute '{attribute.qualified_name}' looks "
                    "sensitive but is stored unencrypted, so anyone "
                    "with database or service-centre access reads it "
                    "in clear text.",
                "recommendation":
                    "Encrypt the attribute, or hash it if it only ever "
                    "needs to be compared, and restrict which modules "
                    "may read the entity.",
                "evidence": {
                    "data_type": attribute.data_type,
                    "matched": secret or personal,
                    "category": "credential" if secret else "personal",
                },
            }
        ]

    def _site_property(
        self,
        site_property: SiteProperty,
    ) -> list[dict[str, Any]]:
        if not site_property.default_value:
            return []

        if not _matches(site_property.name, SECRET_PATTERNS):
            return []

        return [
            {
                "rule_id": "OSSEC-104",
                "severity": "high",
                "location": site_property.qualified_name,
                "module": site_property.module,
                "risk":
                    f"Site property '{site_property.qualified_name}' "
                    "ships with a secret as its default value, so the "
                    "credential lives in the module's source and in "
                    "every environment it is published to.",
                "recommendation":
                    "Clear the default value and set the secret per "
                    "environment in Service Center, or read it from a "
                    "vault at runtime.",
                "evidence": {
                    "data_type": site_property.data_type,
                    "has_default_value": True,
                },
            }
        ]

    def _query(self, query: Query) -> list[dict[str, Any]]:
        if not query.inline_parameters:
            return []

        return [
            {
                "rule_id": "OSSEC-106",
                "severity": "critical",
                "location": query.qualified_name,
                "module": query.module,
                "risk":
                    f"Advanced SQL '{query.qualified_name}' expands "
                    f"{', '.join(query.inline_parameters)} inline, so "
                    "the parameter value becomes part of the statement "
                    "and a crafted value changes the query.",
                "recommendation":
                    "Turn off 'Expand Inline' so the parameter is "
                    "bound, or validate the value against a fixed list "
                    "when it must be a column or table name.",
                "evidence": {
                    "kind": query.kind,
                    "inline_parameters": query.inline_parameters,
                },
            }
        ]

    def _consumed_api(self, api: ConsumedApi) -> list[dict[str, Any]]:
        if not api.base_url.lower().startswith("http://"):
            return []

        return [
            {
                "rule_id": "OSSEC-107",
                "severity": "medium",
                "location": api.qualified_name,
                "module": api.module,
                "risk":
                    f"Consumed API '{api.qualified_name}' is called "
                    "over plain HTTP, so its payloads and any "
                    "credentials it sends travel unencrypted.",
                "recommendation":
                    "Point the effective URL at the HTTPS endpoint and "
                    "keep certificate validation on.",
                "evidence": {
                    "base_url": api.base_url,
                },
            }
        ]


__all__ = [
    "OPEN_AUTHENTICATION",
    "OutSystemsSecurityAnalyzer",
]
