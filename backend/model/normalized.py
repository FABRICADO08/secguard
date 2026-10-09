from __future__ import annotations

from typing import Any


EMPTY_MODEL: dict[str, list] = {
    "modules": [],
    "entities": [],
    "attributes": [],
    "associations": [],
    "microflows": [],
    "nanoflows": [],
    "pages": [],
    "roles": [],
    "module_roles": [],
    "access_rules": [],
    "apis": [],
}


def create_empty_model() -> dict[str, list]:

    return {
        key: list(value)
        for key, value in EMPTY_MODEL.items()
    }


def normalize_model(
    model: dict[str, Any] | None,
) -> dict[str, list]:

    normalized = create_empty_model()

    if not model:
        return normalized

    for key in normalized:

        value = model.get(
            key,
            [],
        )

        if isinstance(
            value,
            list,
        ):

            normalized[key] = value

    return normalized


def model_statistics(
    model: dict[str, Any],
) -> dict[str, int]:

    normalized = normalize_model(
        model
    )

    return {
        key:
            len(value)
        for key, value
        in normalized.items()
    }


def platform_model_statistics(
    platform: str,
    model: dict[str, Any],
) -> dict[str, int]:
    """Return normalized entity counts for Mendix or OutSystems models."""
    if str(platform or "").lower() == "outsystems":
        return {
            key: len(model.get(key) or [])
            for key in (
                "modules",
                "entities",
                "screens",
                "rest_methods",
                "consumed_apis",
                "site_properties",
                "queries",
                "roles",
            )
        }
    return model_statistics(model)