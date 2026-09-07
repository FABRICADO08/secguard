from __future__ import annotations

from typing import Any

from backend.platforms.outsystems.analyzer import OutSystemsSecurityAnalyzer
from backend.platforms.outsystems.findings import to_findings
from backend.platforms.outsystems.model import OutSystemsModel
from backend.platforms.outsystems.parser import OutSystemsModelParser


def model_summary(model: OutSystemsModel) -> dict[str, Any]:
    """
    JSON-safe projection of the parsed model.

    Only the identity of each element and the security-relevant flags
    are kept, so the stored application record stays reviewable.
    """

    return {
        "name": model.name,
        "modules": [
            {
                "name": module.name,
                "kind": module.kind,
                "entity_count": len(module.entities),
                "screen_count": len(module.screens),
                "rest_method_count": len(module.rest_methods),
                "role_count": len(module.roles),
            }
            for module in model.modules
        ],
        "entities": [
            {
                "name": entity.name,
                "qualified_name": entity.qualified_name,
                "module": entity.module,
                "public": entity.is_public,
                "expose_read_only": entity.expose_read_only,
                "attribute_count": len(entity.attributes),
            }
            for entity in model.entities
        ],
        "screens": [
            {
                "name": screen.name,
                "qualified_name": screen.qualified_name,
                "module": screen.module,
                "anonymous": screen.is_anonymous,
                "roles": screen.roles,
            }
            for screen in model.screens
        ],
        "rest_methods": [
            {
                "name": method.name,
                "qualified_name": method.qualified_name,
                "module": method.module,
                "api": method.api,
                "http_method": method.http_method,
                "authentication": method.authentication,
                "roles": method.roles,
            }
            for method in model.rest_methods
        ],
        "consumed_apis": [
            {
                "name": api.name,
                "qualified_name": api.qualified_name,
                "module": api.module,
                "base_url": api.base_url,
            }
            for api in model.consumed_apis
        ],
        "site_properties": [
            {
                "name": site_property.name,
                "qualified_name": site_property.qualified_name,
                "module": site_property.module,
                "data_type": site_property.data_type,

                # The value itself is a secret when the rule fires, so
                # only its presence is stored.
                "has_default_value": bool(site_property.default_value),
            }
            for site_property in model.site_properties
        ],
        "queries": [
            {
                "name": query.name,
                "qualified_name": query.qualified_name,
                "module": query.module,
                "kind": query.kind,
                "inline_parameters": query.inline_parameters,
            }
            for query in model.queries
        ],
        "roles": model.roles,
    }


def analyze_model(data: dict[str, Any]) -> dict[str, Any]:
    """
    Parse an OutSystems application export and analyze its security.

    Returns the JSON-safe model projection plus normalized findings.
    """

    if not isinstance(data, dict):
        raise ValueError("OutSystems model JSON root must be an object.")

    model = OutSystemsModelParser(data).parse()

    if model.is_empty:

        raise ValueError(
            "No OutSystems model elements were found. Upload an export "
            "containing modules with entities, screens, exposed REST "
            "APIs, site properties or queries."
        )

    findings = to_findings(
        OutSystemsSecurityAnalyzer(model).analyze()
    )

    return {
        "model": model_summary(model),
        "findings": findings,
    }


__all__ = [
    "analyze_model",
    "model_summary",
]
