from __future__ import annotations

from typing import Any

from backend.platforms.mendix.analyzer import MendixSecurityAnalyzer
from backend.platforms.mendix.findings import to_findings
from backend.platforms.mendix.model import MendixModel
from backend.platforms.mendix.parser import MendixModelParser


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


def model_summary(model: MendixModel) -> dict[str, Any]:
    """
    JSON-safe projection of the parsed model.

    The parsed model holds nested dataclasses that are neither
    serializable nor useful to a reviewer, so only the identity of each
    element and the security-relevant flags are kept.
    """

    return {
        "modules": [
            {
                "name": _field(module, "name", ""),
                "qualified_name": _field(module, "qualified_name", ""),
                "entity_count": len(_field(module, "entities", [])),
            }
            for module in model.modules
        ],
        "entities": [
            {
                "name": _field(entity, "name", ""),
                "qualified_name": _field(entity, "qualified_name", ""),
                "module": _field(entity, "module", ""),
                "attribute_count": len(_field(entity, "attributes", [])),
                "access_rule_count": len(
                    _field(entity, "access_rules", [])
                ),
            }
            for entity in model.entities
        ],
        "attributes": _identity(model.attributes),
        "associations": [
            {
                "name": _field(association, "name", ""),
                "qualified_name": _field(
                    association, "qualified_name", ""
                ),
                "parent": _field(association, "parent", ""),
                "child": _field(association, "child", ""),
                "parent_delete_behavior": _field(
                    association, "parent_delete_behavior", ""
                ),
                "child_delete_behavior": _field(
                    association, "child_delete_behavior", ""
                ),
            }
            for association in model.associations
        ],
        "microflows": [
            {
                "name": _field(microflow, "name", ""),
                "qualified_name": _field(
                    microflow, "qualified_name", ""
                ),
                "module": _field(microflow, "module", ""),
                "apply_entity_access": bool(
                    _field(microflow, "apply_entity_access", True)
                ),
                "allowed_module_roles": list(
                    _field(microflow, "allowed_module_roles", [])
                ),
            }
            for microflow in model.microflows
        ],
        "nanoflows": [],
        "pages": [
            {
                "name": _field(page, "name", ""),
                "qualified_name": _field(page, "qualified_name", ""),
                "module": _field(page, "module", ""),
                "allowed_module_roles": list(
                    _field(page, "allowed_module_roles", [])
                    or _field(page, "allowed_roles", [])
                ),
            }
            for page in model.pages
        ],
        "roles": [],
        "module_roles": _identity(model.module_roles),
        "access_rules": [
            {
                "entity": _field(rule, "entity", ""),
                "roles": list(_field(rule, "roles", [])),
                "allow_create": bool(_field(rule, "allow_create", False)),
                "allow_delete": bool(_field(rule, "allow_delete", False)),
                "default_member_access_rights": _field(
                    rule, "default_member_access_rights", ""
                ),
                "xpath_constraint": _field(rule, "xpath_constraint", ""),
            }
            for rule in model.access_rules
        ],
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
