from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Attribute:
    name: str
    module: str = ""
    entity: str = ""
    data_type: str = ""
    is_encrypted: bool = False

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.entity, self.name)
            if part
        )


@dataclass
class Entity:
    name: str
    module: str = ""
    is_public: bool = False
    expose_read_only: bool = False
    attributes: list[Attribute] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Screen:
    name: str
    module: str = ""
    is_anonymous: bool = False
    roles: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class RestMethod:
    name: str
    api: str = ""
    module: str = ""
    http_method: str = ""
    authentication: str = ""
    roles: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.api, self.name)
            if part
        )


@dataclass
class ConsumedApi:
    name: str
    module: str = ""
    base_url: str = ""

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class SiteProperty:
    name: str
    module: str = ""
    data_type: str = ""
    default_value: str = ""

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Query:
    name: str
    module: str = ""
    kind: str = ""
    sql: str = ""
    inline_parameters: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Module:
    name: str
    kind: str = ""
    entities: list[Entity] = field(default_factory=list)
    screens: list[Screen] = field(default_factory=list)
    rest_methods: list[RestMethod] = field(default_factory=list)
    consumed_apis: list[ConsumedApi] = field(default_factory=list)
    site_properties: list[SiteProperty] = field(default_factory=list)
    queries: list[Query] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)


@dataclass
class OutSystemsModel:
    """Flattened view of an OutSystems application export."""

    name: str = ""
    modules: list[Module] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    screens: list[Screen] = field(default_factory=list)
    rest_methods: list[RestMethod] = field(default_factory=list)
    consumed_apis: list[ConsumedApi] = field(default_factory=list)
    site_properties: list[SiteProperty] = field(default_factory=list)
    queries: list[Query] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.modules,
                self.entities,
                self.screens,
                self.rest_methods,
                self.consumed_apis,
                self.site_properties,
                self.queries,
            )
        )


__all__ = [
    "Attribute",
    "ConsumedApi",
    "Entity",
    "Module",
    "OutSystemsModel",
    "Query",
    "RestMethod",
    "Screen",
    "SiteProperty",
]
