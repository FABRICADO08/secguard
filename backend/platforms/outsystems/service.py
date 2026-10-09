from __future__ import annotations

from typing import Any

from backend.platforms.errors import EmptyModelError
from backend.platforms.outsystems.analyzer import OutSystemsSecurityAnalyzer
from backend.platforms.outsystems.findings import to_findings
from backend.platforms.outsystems.model import OutSystemsModel
from backend.platforms.outsystems.parser import OutSystemsModelParser

EMPTY_MODEL = (
    "No OutSystems model elements were found. Upload an export "
    "containing modules with entities, screens, exposed REST "
    "APIs, site properties or queries."
)


def _modules_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": module.name,
            "kind": module.kind,
            "entity_count": len(module.entities),
            "screen_count": len(module.screens),
            "rest_method_count": len(module.rest_methods),
            "role_count": len(module.roles),
        }
        for module in model.modules
    ]


def _entities_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": entity.name,
            "qualified_name": entity.qualified_name,
            "module": entity.module,
            "public": entity.is_public,
            "expose_read_only": entity.expose_read_only,
            "attribute_count": len(entity.attributes),
        }
        for entity in model.entities
    ]


def _screens_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": screen.name,
            "qualified_name": screen.qualified_name,
            "module": screen.module,
            "anonymous": screen.is_anonymous,
            "roles": screen.roles,
        }
        for screen in model.screens
    ]


def _rest_methods_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
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
    ]


def _consumed_apis_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": api.name,
            "qualified_name": api.qualified_name,
            "module": api.module,
            "base_url": api.base_url,
        }
        for api in model.consumed_apis
    ]


def _site_properties_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": item.name,
            "qualified_name": item.qualified_name,
            "module": item.module,
            "data_type": item.data_type,
            # The value itself is a secret when the rule fires, so only its presence is stored.
            "has_default_value": bool(item.default_value),
        }
        for item in model.site_properties
    ]


def _queries_summary(model: OutSystemsModel) -> list[dict[str, Any]]:
    return [
        {
            "name": query.name,
            "qualified_name": query.qualified_name,
            "module": query.module,
            "kind": query.kind,
            "inline_parameters": query.inline_parameters,
        }
        for query in model.queries
    ]


def model_summary(model: OutSystemsModel) -> dict[str, Any]:
    """
    JSON-safe projection of the parsed model.

    Only the identity of each element and the security-relevant flags
    are kept, so the stored application record stays reviewable.
    """

    return {
        "name": model.name,
        "modules": _modules_summary(model),
        "entities": _entities_summary(model),
        "screens": _screens_summary(model),
        "rest_methods": _rest_methods_summary(model),
        "consumed_apis": _consumed_apis_summary(model),
        "site_properties": _site_properties_summary(model),
        "queries": _queries_summary(model),
        "roles": model.roles,
    }


def analyze_model(data: dict[str, Any]) -> dict[str, Any]:
    """
    Parse an OutSystems application export and analyze its security.

    Returns the JSON-safe model projection plus normalized findings.
    """

    if not isinstance(data, dict):
        # ValueError so the route reports it as a 400 like every other
        # malformed upload, rather than an unexpected failure.
        raise ValueError(  # noqa: TRY004
            "OutSystems model JSON root must be an object."
        )

    model = OutSystemsModelParser(data).parse()

    if model.is_empty:

        raise EmptyModelError(EMPTY_MODEL)

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
