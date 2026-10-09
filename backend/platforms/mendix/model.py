"""Typed records and lookup helpers for normalized Mendix exports."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ============================================================
# ATTRIBUTE
# ============================================================

@dataclass
class Attribute:
    """A named entity attribute and its normalized model metadata."""

    name: str

    qualified_name: str = ""

    type: str = ""

    length: Optional[int] = None

    owner: str = ""

    documentation: str = ""


# ============================================================
# MEMBER ACCESS
# ============================================================

@dataclass
class MemberAccess:
    """
    Represents access to a specific entity member/attribute.

    Mendix entity access rules can define more restrictive
    permissions for individual members.
    """

    member: str = ""

    member_qualified_name: str = ""

    access_rights: str = ""

    readable: bool = False

    writable: bool = False

    executable: bool = False

    documentation: str = ""


# ============================================================
# ENTITY ACCESS RULE
# ============================================================

@dataclass
class AccessRule:
    """
    Normalized representation of a Mendix DomainModels$AccessRule.

    In the Mendix model dump, entity access rules are located
    inside an Entity's accessRules collection.
    """

    entity: str = ""

    entity_qualified_name: str = ""

    roles: List[str] = field(
        default_factory=list
    )

    allow_create: bool = False

    allow_delete: bool = False

    default_member_access_rights: str = ""

    xpath_constraint: str = ""

    xpath_constraint_caption: str = ""

    member_accesses: List[Dict[str, Any]] = field(
        default_factory=list
    )

    documentation: str = ""

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def has_xpath_constraint(self) -> bool:
        """Whether the rule restricts visible records with an XPath clause."""
        return bool(
            self.xpath_constraint.strip()
        )

    @property
    def has_create_access(self) -> bool:
        """Whether the rule permits record creation."""
        return self.allow_create

    @property
    def has_delete_access(self) -> bool:
        """Whether the rule permits record deletion."""
        return self.allow_delete

    @property
    def has_write_access(self) -> bool:
        """Whether the rule permits any write operation."""

        if self.allow_create:
            return True

        if self.allow_delete:
            return True

        access = (
            self.default_member_access_rights
            or ""
        ).lower()

        return access in {
            "write",
            "readwrite",
            "read_write",
            "full",
        }


# ============================================================
# ASSOCIATION
# ============================================================

@dataclass
class Association:
    """A relationship between two normalized Mendix entities."""

    name: str

    qualified_name: str = ""

    parent: str = ""

    child: str = ""

    association_type: str = ""

    owner: str = ""

    documentation: str = ""


# ============================================================
# ENTITY
# ============================================================

@dataclass
class Entity:
    """A Mendix entity with its attributes and access rules."""

    name: str

    qualified_name: str = ""

    module: str = ""

    persistable: bool = True

    generalization: str = ""

    documentation: str = ""

    attributes: List[Attribute] = field(
        default_factory=list
    )

    associations: List[Association] = field(
        default_factory=list
    )

    access_rules: List[AccessRule] = field(
        default_factory=list
    )

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def has_access_rules(self) -> bool:
        """Whether any access rule is defined for this entity."""
        return len(
            self.access_rules
        ) > 0

    @property
    def has_write_access(self) -> bool:
        """Whether an entity-level access rule permits writes."""

        for rule in self.access_rules:

            if rule.has_write_access:
                return True

        return False

    @property
    def has_delete_access(self) -> bool:
        """Whether an access rule permits deleting entity records."""

        for rule in self.access_rules:

            if rule.allow_delete:
                return True

        return False

    @property
    def has_create_access(self) -> bool:
        """Whether an access rule permits creating entity records."""

        for rule in self.access_rules:

            if rule.allow_create:
                return True

        return False

    @property
    def has_xpath_restriction(self) -> bool:
        """Whether any access rule limits records with an XPath clause."""

        for rule in self.access_rules:

            if rule.has_xpath_constraint:
                return True

        return False


# ============================================================
# MODULE ROLE
# ============================================================

@dataclass
class ModuleRole:
    """A role defined within a Mendix module."""

    name: str

    qualified_name: str = ""

    module: str = ""

    documentation: str = ""


# ============================================================
# MODULE
# ============================================================

@dataclass
class Module:
    """A Mendix module and its directly owned model elements."""

    name: str

    qualified_name: str = ""

    module_roles: List[ModuleRole] = field(
        default_factory=list
    )

    entities: List[Entity] = field(
        default_factory=list
    )

    documentation: str = ""

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def entity_count(self) -> int:
        """Return the number of entities in this module."""
        return len(
            self.entities
        )

    @property
    def role_count(self) -> int:
        """Return the number of roles in this module."""
        return len(
            self.module_roles
        )


# ============================================================
# MICROFLOW
# ============================================================

@dataclass
class Microflow:
    """A server-side flow and its role/access-control settings."""

    name: str

    qualified_name: str = ""

    module: str = ""

    allowed_module_roles: List[str] = field(
        default_factory=list
    )

    apply_entity_access: bool = True

    return_type: str = ""

    documentation: str = ""

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def is_restricted(self) -> bool:
        """Whether the flow is limited to one or more module roles."""
        return len(
            self.allowed_module_roles
        ) > 0

    @property
    def bypasses_entity_access(self) -> bool:
        """Whether the flow runs without entity access checks."""
        return not self.apply_entity_access


# ============================================================
# PAGE
# ============================================================

@dataclass
class Page:
    """A Mendix page and its role-based visibility settings."""

    name: str

    qualified_name: str = ""

    module: str = ""

    allowed_module_roles: List[str] = field(
        default_factory=list
    )

    documentation: str = ""

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def is_restricted(self) -> bool:
        """Whether the page is limited to one or more module roles."""
        return len(
            self.allowed_module_roles
        ) > 0


# ============================================================
# MENDIX MODEL
# ============================================================

@dataclass
class MendixModel:
    """Normalized collections of the model elements in a Mendix export."""

    modules: List[Module] = field(
        default_factory=list
    )

    entities: List[Entity] = field(
        default_factory=list
    )

    attributes: List[Attribute] = field(
        default_factory=list
    )

    associations: List[Association] = field(
        default_factory=list
    )

    microflows: List[Microflow] = field(
        default_factory=list
    )

    pages: List[Page] = field(
        default_factory=list
    )

    module_roles: List[ModuleRole] = field(
        default_factory=list
    )

    access_rules: List[AccessRule] = field(
        default_factory=list
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    def statistics(self) -> Dict[str, int]:
        """Count the principal model element types."""

        return {
            "modules":
                len(self.modules),

            "entities":
                len(self.entities),

            "attributes":
                len(self.attributes),

            "associations":
                len(self.associations),

            "microflows":
                len(self.microflows),

            "pages":
                len(self.pages),

            "module_roles":
                len(self.module_roles),

            "access_rules":
                len(self.access_rules),
        }

    # ========================================================
    # SECURITY STATISTICS
    # ========================================================

    def security_statistics(
        self,
    ) -> Dict[str, int]:
        """Summarize entity and microflow access-control characteristics."""

        entities_without_rules = 0

        entities_with_create = 0

        entities_with_delete = 0

        entities_with_xpath = 0

        microflows_bypassing_access = 0

        for entity in self.entities:

            if not entity.access_rules:

                entities_without_rules += 1

            if entity.has_create_access:

                entities_with_create += 1

            if entity.has_delete_access:

                entities_with_delete += 1

            if entity.has_xpath_restriction:

                entities_with_xpath += 1

        for microflow in self.microflows:

            if microflow.bypasses_entity_access:

                microflows_bypassing_access += 1

        return {
            "entities_without_access_rules":
                entities_without_rules,

            "entities_with_create_access":
                entities_with_create,

            "entities_with_delete_access":
                entities_with_delete,

            "entities_with_xpath_restrictions":
                entities_with_xpath,

            "microflows_bypassing_entity_access":
                microflows_bypassing_access,
        }

    # ========================================================
    # FIND ENTITY
    # ========================================================

    def find_entity(
        self,
        name: str,
    ) -> Optional[Entity]:
        """Find an entity by simple or qualified name."""

        for entity in self.entities:

            if (
                entity.name == name
                or
                entity.qualified_name == name
            ):

                return entity

        return None

    # ========================================================
    # FIND MODULE
    # ========================================================

    def find_module(
        self,
        name: str,
    ) -> Optional[Module]:
        """Find a module by simple or qualified name."""

        for module in self.modules:

            if (
                module.name == name
                or
                module.qualified_name == name
            ):

                return module

        return None

    # ========================================================
    # FIND ROLE
    # ========================================================

    def find_role(
        self,
        name: str,
    ) -> Optional[ModuleRole]:
        """Find a role by simple or qualified name."""

        for role in self.module_roles:

            if (
                role.name == name
                or
                role.qualified_name == name
            ):

                return role

        return None

    # ========================================================
    # FIND MICROFLOW
    # ========================================================

    def find_microflow(
        self,
        name: str,
    ) -> Optional[Microflow]:
        """Find a microflow by simple or qualified name."""

        for microflow in self.microflows:

            if (
                microflow.name == name
                or
                microflow.qualified_name == name
            ):

                return microflow

        return None

    # ========================================================
    # FIND PAGE
    # ========================================================

    def find_page(
        self,
        name: str,
    ) -> Optional[Page]:
        """Find a page by simple or qualified name."""

        for page in self.pages:

            if (
                page.name == name
                or
                page.qualified_name == name
            ):

                return page

        return None

    # ========================================================
    # SERIALIZATION
    # ========================================================

    def to_dict(
        self,
    ) -> Dict[str, Any]:
        """Serialize model collections to JSON-compatible dictionaries."""

        return {
            "modules": [
                module.__dict__
                for module in self.modules
            ],

            "entities": [
                entity.__dict__
                for entity in self.entities
            ],

            "attributes": [
                attribute.__dict__
                for attribute in self.attributes
            ],

            "associations": [
                association.__dict__
                for association in self.associations
            ],

            "microflows": [
                microflow.__dict__
                for microflow in self.microflows
            ],

            "pages": [
                page.__dict__
                for page in self.pages
            ],

            "module_roles": [
                role.__dict__
                for role in self.module_roles
            ],

            "access_rules": [
                rule.__dict__
                for rule in self.access_rules
            ],

            "statistics":
                self.statistics(),

            "security_statistics":
                self.security_statistics(),
        }