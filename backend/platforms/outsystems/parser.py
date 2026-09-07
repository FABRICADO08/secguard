from __future__ import annotations

from typing import Any

from backend.platforms.outsystems.model import (
    Attribute,
    ConsumedApi,
    Entity,
    Module,
    OutSystemsModel,
    Query,
    RestMethod,
    Screen,
    SiteProperty,
)


def _get(source: dict[str, Any], *names: str, default: Any = None) -> Any:
    """
    Read the first present key.

    Exports differ in casing between the Service Studio, the Lifetime API
    and hand-written documents, so every field is looked up under each
    spelling it is known by.
    """

    for name in names:

        if name in source:
            value = source[name]

            if value is not None:
                return value

    return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}

    return bool(value)


def _items(source: dict[str, Any], *names: str) -> list[dict[str, Any]]:
    value = _get(source, *names, default=[])

    if isinstance(value, dict):
        value = list(value.values())

    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


def _names(value: Any) -> list[str]:
    """Role references may be plain strings or objects with a name."""

    if isinstance(value, dict):
        value = list(value.values())

    if not isinstance(value, list):
        return []

    names = []

    for item in value:

        if isinstance(item, dict):
            item = _get(item, "name", "Name", "role", "Role", default="")

        name = _text(item)

        if name:
            names.append(name)

    return names


class OutSystemsModelParser:
    """
    Reads an OutSystems application export into the flattened model.

    Unknown keys are ignored and missing collections are treated as
    empty, so a partial export still yields whatever it does describe.
    """

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document if isinstance(document, dict) else {}

    def parse(self) -> OutSystemsModel:
        model = OutSystemsModel(
            name=_text(
                _get(
                    self.document,
                    "name",
                    "Name",
                    "application",
                    "Application",
                )
            )
        )

        for raw in _items(
            self.document,
            "modules",
            "Modules",
            "espaces",
            "eSpaces",
        ):
            module = self._module(raw)

            model.modules.append(module)

            model.entities.extend(module.entities)
            model.screens.extend(module.screens)
            model.rest_methods.extend(module.rest_methods)
            model.consumed_apis.extend(module.consumed_apis)
            model.site_properties.extend(module.site_properties)
            model.queries.extend(module.queries)

            for role in module.roles:

                if role not in model.roles:
                    model.roles.append(role)

        return model

    def _module(self, raw: dict[str, Any]) -> Module:
        name = _text(_get(raw, "name", "Name"))

        module = Module(
            name=name,
            kind=_text(_get(raw, "kind", "Kind", "type", "Type")),
            roles=_names(_get(raw, "roles", "Roles")),
        )

        module.entities = [
            self._entity(item, name)
            for item in _items(raw, "entities", "Entities")
        ]

        module.screens = [
            self._screen(item, name)
            for item in _items(raw, "screens", "Screens", "pages", "Pages")
        ]

        module.rest_methods = self._rest_methods(raw, name)

        module.consumed_apis = [
            ConsumedApi(
                name=_text(_get(item, "name", "Name")),
                module=name,
                base_url=_text(
                    _get(
                        item,
                        "baseUrl",
                        "base_url",
                        "BaseUrl",
                        "url",
                        "Url",
                    )
                ),
            )
            for item in _items(
                raw,
                "consumedRestApis",
                "consumed_rest_apis",
                "ConsumedRestApis",
                "consumedApis",
            )
        ]

        module.site_properties = [
            SiteProperty(
                name=_text(_get(item, "name", "Name")),
                module=name,
                data_type=_text(
                    _get(item, "dataType", "data_type", "DataType")
                ),
                default_value=_text(
                    _get(
                        item,
                        "defaultValue",
                        "default_value",
                        "DefaultValue",
                        "value",
                        "Value",
                    )
                ),
            )
            for item in _items(
                raw,
                "siteProperties",
                "site_properties",
                "SiteProperties",
            )
        ]

        module.queries = [
            self._query(item, name)
            for item in _items(raw, "queries", "Queries")
        ]

        return module

    def _entity(self, raw: dict[str, Any], module: str) -> Entity:
        name = _text(_get(raw, "name", "Name"))

        return Entity(
            name=name,
            module=module,
            is_public=_bool(_get(raw, "public", "isPublic", "IsPublic")),
            expose_read_only=_bool(
                _get(
                    raw,
                    "exposeReadOnly",
                    "expose_read_only",
                    "ExposeReadOnly",
                )
            ),
            attributes=[
                Attribute(
                    name=_text(_get(item, "name", "Name")),
                    module=module,
                    entity=name,
                    data_type=_text(
                        _get(item, "dataType", "data_type", "DataType")
                    ),
                    is_encrypted=_bool(
                        _get(
                            item,
                            "isEncrypted",
                            "is_encrypted",
                            "IsEncrypted",
                            "encrypted",
                        )
                    ),
                )
                for item in _items(raw, "attributes", "Attributes")
            ],
        )

    def _screen(self, raw: dict[str, Any], module: str) -> Screen:
        roles = _names(_get(raw, "roles", "Roles"))

        anonymous = _bool(
            _get(
                raw,
                "anonymous",
                "isAnonymous",
                "IsAnonymous",
                "allowAnonymous",
            )
        )

        return Screen(
            name=_text(_get(raw, "name", "Name")),
            module=module,
            is_anonymous=anonymous,
            roles=roles,
        )

    def _rest_methods(
        self,
        raw: dict[str, Any],
        module: str,
    ) -> list[RestMethod]:
        methods = []

        for api in _items(
            raw,
            "exposedRestApis",
            "exposed_rest_apis",
            "ExposedRestApis",
            "restApis",
        ):
            api_name = _text(_get(api, "name", "Name"))

            api_authentication = _text(
                _get(api, "authentication", "Authentication")
            )

            api_roles = _names(_get(api, "roles", "Roles"))

            for item in _items(api, "methods", "Methods"):

                methods.append(
                    RestMethod(
                        name=_text(_get(item, "name", "Name")),
                        api=api_name,
                        module=module,
                        http_method=_text(
                            _get(
                                item,
                                "httpMethod",
                                "http_method",
                                "HttpMethod",
                                "verb",
                            )
                        ),
                        authentication=_text(
                            _get(item, "authentication", "Authentication")
                        )
                        or api_authentication,
                        roles=_names(_get(item, "roles", "Roles"))
                        or api_roles,
                    )
                )

        return methods

    def _query(self, raw: dict[str, Any], module: str) -> Query:
        return Query(
            name=_text(_get(raw, "name", "Name")),
            module=module,
            kind=_text(_get(raw, "kind", "Kind", "type", "Type")),
            sql=_text(_get(raw, "sql", "Sql", "SQL", "statement")),
            inline_parameters=_names(
                _get(
                    raw,
                    "expandInline",
                    "expand_inline",
                    "ExpandInline",
                    "inlineParameters",
                )
            ),
        )


__all__ = ["OutSystemsModelParser"]
