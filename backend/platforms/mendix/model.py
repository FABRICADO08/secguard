from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ============================================================
# ATTRIBUTE
# ============================================================

@dataclass
class Attribute:
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
        return bool(
            self.xpath_constraint.strip()
        )

    @property
    def has_create_access(self) -> bool:
        return self.allow_create

    @property
    def has_delete_access(self) -> bool:
        return self.allow_delete

    @property
    def has_write_access(self) -> bool:

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
        return len(
            self.access_rules
        ) > 0

    @property
    def has_write_access(self) -> bool:

        for rule in self.access_rules:

            if rule.has_write_access:
                return True

        return False

    @property
    def has_delete_access(self) -> bool:

        for rule in self.access_rules:

            if rule.allow_delete:
                return True

        return False

    @property
    def has_create_access(self) -> bool:

        for rule in self.access_rules:

            if rule.allow_create:
                return True

        return False

    @property
    def has_xpath_restriction(self) -> bool:

        for rule in self.access_rules:

            if rule.has_xpath_constraint:
                return True

        return False


# ============================================================
# MODULE ROLE
# ============================================================

@dataclass
class ModuleRole:
    name: str

    qualified_name: str = ""

    module: str = ""

    documentation: str = ""


# ============================================================
# MODULE
# ============================================================

@dataclass
class Module:
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
        return len(
            self.entities
        )

    @property
    def role_count(self) -> int:
        return len(
            self.module_roles
        )


# ============================================================
# MICROFLOW
# ============================================================

@dataclass
class Microflow:
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
        return len(
            self.allowed_module_roles
        ) > 0

    @property
    def bypasses_entity_access(self) -> bool:
        return not self.apply_entity_access


# ============================================================
# PAGE
# ============================================================

@dataclass
class Page:
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
        return len(
            self.allowed_module_roles
        ) > 0


# ============================================================
# MENDIX MODEL
# ============================================================

@dataclass
class MendixModel:

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