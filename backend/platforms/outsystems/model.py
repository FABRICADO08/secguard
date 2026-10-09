"""Typed records used to normalize OutSystems application exports."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Attribute:
    """An attribute declared on an OutSystems entity."""

    name: str
    module: str = ""
    entity: str = ""
    data_type: str = ""
    is_encrypted: bool = False

    @property
    def qualified_name(self) -> str:
        """Return the module, entity, and attribute name joined together."""
        return ".".join(
            part
            for part in (self.module, self.entity, self.name)
            if part
        )


@dataclass
class Entity:
    """An entity and its exposure and attribute metadata."""

    name: str
    module: str = ""
    is_public: bool = False
    expose_read_only: bool = False
    attributes: list[Attribute] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        """Return the module-qualified entity name."""
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Screen:
    """A screen with its anonymous-access and role settings."""

    name: str
    module: str = ""
    is_anonymous: bool = False
    roles: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        """Return the module-qualified screen name."""
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class RestMethod:
    """An exposed REST method and its access-control metadata."""

    name: str
    api: str = ""
    module: str = ""
    http_method: str = ""
    authentication: str = ""
    roles: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        """Return the module, API, and method names joined together."""
        return ".".join(
            part
            for part in (self.module, self.api, self.name)
            if part
        )


@dataclass
class ConsumedApi:
    """An external API consumed by an OutSystems module."""

    name: str
    module: str = ""
    base_url: str = ""

    @property
    def qualified_name(self) -> str:
        """Return the module-qualified API name."""
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class SiteProperty:
    """A configurable site property, including its default value."""

    name: str
    module: str = ""
    data_type: str = ""
    default_value: str = ""

    @property
    def qualified_name(self) -> str:
        """Return the module-qualified site-property name."""
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Query:
    """A database query and any parameters expanded inline."""

    name: str
    module: str = ""
    kind: str = ""
    sql: str = ""
    inline_parameters: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        """Return the module-qualified query name."""
        return ".".join(
            part
            for part in (self.module, self.name)
            if part
        )


@dataclass
class Module:
    """All security-relevant model elements owned by one module."""

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
        """Whether the normalized export contains any model elements."""
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
