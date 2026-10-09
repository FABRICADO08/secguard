from __future__ import annotations

from typing import Any

from backend.platforms.errors import EmptyModelError
from backend.platforms.mendix.analyzer import MendixSecurityAnalyzer
from backend.platforms.mendix.findings import to_findings
from backend.platforms.mendix.model import MendixModel
from backend.platforms.mendix.parser import MendixModelParser

EMPTY_MODEL = (
    "No Mendix model elements were found. Upload a dump-mpr "
    "JSON export containing modules, entities, microflows, "
    "pages or security roles."
)


def _field(element: Any, name: str, default: Any) -> Any:
    """
    Read a model element field.

    MendixModelParser falls back to ``cls.__new__`` when a model class
    does not accept every parsed keyword, so elements can legitimately
    miss dataclass fields that would otherwise always be present.
    """

    value = getattr(element, name, default)

    return default if value is None else value


def _identity(elements: list[Any]) -> list[dict[str, str]]:
    return [
        {
            "name": _field(element, "name", ""),
            "qualified_name": _field(element, "qualified_name", ""),
            "module": _field(element, "module", ""),
        }
        for element in elements
    ]


def _model_modules(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "name": _field(module, "name", ""),
            "qualified_name": _field(module, "qualified_name", ""),
            "entity_count": len(_field(module, "entities", [])),
        }
        for module in model.modules
    ]


def _model_entities(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "name": _field(entity, "name", ""),
            "qualified_name": _field(entity, "qualified_name", ""),
            "module": _field(entity, "module", ""),
            "attribute_count": len(_field(entity, "attributes", [])),
            "access_rule_count": len(_field(entity, "access_rules", [])),
        }
        for entity in model.entities
    ]


def _model_associations(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "name": _field(item, "name", ""),
            "qualified_name": _field(item, "qualified_name", ""),
            "parent": _field(item, "parent", ""),
            "child": _field(item, "child", ""),
            "parent_delete_behavior": _field(item, "parent_delete_behavior", ""),
            "child_delete_behavior": _field(item, "child_delete_behavior", ""),
        }
        for item in model.associations
    ]


def _model_flows(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "name": _field(item, "name", ""),
            "qualified_name": _field(item, "qualified_name", ""),
            "module": _field(item, "module", ""),
            "apply_entity_access": bool(_field(item, "apply_entity_access", True)),
            "allowed_module_roles": list(_field(item, "allowed_module_roles", [])),
        }
        for item in model.microflows
    ]


def _model_pages(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "name": _field(item, "name", ""),
            "qualified_name": _field(item, "qualified_name", ""),
            "module": _field(item, "module", ""),
            "allowed_module_roles": list(
                _field(item, "allowed_module_roles", [])
                or _field(item, "allowed_roles", [])
            ),
        }
        for item in model.pages
    ]


def _model_access_rules(model: MendixModel) -> list[dict[str, Any]]:
    return [
        {
            "entity": _field(item, "entity", ""),
            "roles": list(_field(item, "roles", [])),
            "allow_create": bool(_field(item, "allow_create", False)),
            "allow_delete": bool(_field(item, "allow_delete", False)),
            "default_member_access_rights": _field(
                item, "default_member_access_rights", ""
            ),
            "xpath_constraint": _field(item, "xpath_constraint", ""),
        }
        for item in model.access_rules
    ]


def model_summary(model: MendixModel) -> dict[str, Any]:
    """
    JSON-safe projection of the parsed model.

    The parsed model holds nested dataclasses that are neither
    serializable nor useful to a reviewer, so only the identity of each
    element and the security-relevant flags are kept.
    """

    return {
        "modules": _model_modules(model),
        "entities": _model_entities(model),
        "attributes": _identity(model.attributes),
        "associations": _model_associations(model),
        "microflows": _model_flows(model),
        "nanoflows": [],
        "pages": _model_pages(model),
        "roles": [],
        "module_roles": _identity(model.module_roles),
        "access_rules": _model_access_rules(model),
        "apis": [],
    }


def analyze_model(data: dict[str, Any]) -> dict[str, Any]:
    """
    Parse a Mendix dump-mpr JSON document and analyze its security.

    Returns the JSON-safe model projection plus normalized findings.
    """

    if not isinstance(data, dict):
        raise ValueError("Mendix model JSON root must be an object.")

    model = MendixModelParser(data).parse()

    if not any(
        (
            model.modules,
            model.entities,
            model.microflows,
            model.pages,
            model.module_roles,
            model.associations,
        )
    ):
        raise EmptyModelError(EMPTY_MODEL)

    findings = to_findings(
        MendixSecurityAnalyzer(model).analyze()
    )

    return {
        "model": model_summary(model),
        "findings": findings,
    }


__all__ = [
    "analyze_model",
    "model_summary",
]
