from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .model import (
    MendixModel,
    Module,
    Entity,
    Attribute,
    Association,
    Microflow,
    Page,
    ModuleRole,
    AccessRule,
)


class MendixModelParser:
    """
    Parser for Mendix dump-mpr JSON.

    Important Mendix model structures:

        Entity
        ├── attributes[]
        └── accessRules[]

        Association
        ├── parent = Entity $ID
        └── child  = Entity $ID

    Associations are standalone DomainModels$Association
    objects and therefore require a second resolution phase.
    """

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        data: Dict[str, Any],
    ):

        self.data = data

        self.model = MendixModel()

        # --------------------------------------------------------
        # Entity indexes
        # --------------------------------------------------------

        self.entities_by_name: Dict[
            str,
            Entity,
        ] = {}

        self.entities_by_id: Dict[
            str,
            Entity,
        ] = {}

        # --------------------------------------------------------
        # Other indexes
        # --------------------------------------------------------

        self.attributes_by_name: Dict[
            str,
            Attribute,
        ] = {}

        self.associations_by_name: Dict[
            str,
            Association,
        ] = {}

        self.microflows_by_name: Dict[
            str,
            Microflow,
        ] = {}

        self.pages_by_name: Dict[
            str,
            Page,
        ] = {}

        self.modules_by_name: Dict[
            str,
            Module,
        ] = {}

        self.module_roles_by_name: Dict[
            str,
            ModuleRole,
        ] = {}

        self.access_rules_by_id: Dict[
            str,
            AccessRule,
        ] = {}

    # ============================================================
    # FACTORY
    # ============================================================

    @classmethod
    def from_file(
        cls,
        path: Path | str,
    ) -> "MendixModelParser":

        path = Path(path)

        if not path.exists():

            raise FileNotFoundError(
                f"Model file does not exist: {path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if not isinstance(
            data,
            dict,
        ):

            raise ValueError(
                "Mendix model JSON root must be an object."
            )

        return cls(data)

    # ============================================================
    # MAIN PARSE
    # ============================================================

    def parse(
        self,
    ) -> MendixModel:

        # --------------------------------------------------------
        # Parse explicitly declared modules.
        # --------------------------------------------------------

        self._parse_modules()

        # --------------------------------------------------------
        # Parse entities, microflows, pages and roles.
        # --------------------------------------------------------

        self._walk_model(
            self.data
        )

        # --------------------------------------------------------
        # Associations are standalone Mendix model objects.
        # Parse them after entities so their GUIDs can be resolved.
        # --------------------------------------------------------

        self._parse_associations()

        # --------------------------------------------------------
        # Resolve all GUID/name relationships.
        # --------------------------------------------------------

        self._resolve_references()

        return self.model

    # ============================================================
    # GENERIC MODEL WALKER
    # ============================================================

    def _walk_model(
        self,
        value: Any,
    ) -> None:

        if isinstance(
            value,
            dict,
        ):

            node_type = str(
                value.get(
                    "$Type",
                    "",
                )
                or ""
            )

            # ----------------------------------------------------
            # Entity
            #
            # Entity contains its attributes and access rules.
            # Parse it as one complete unit.
            # ----------------------------------------------------

            if node_type == "DomainModels$Entity":

                self._parse_entity(
                    value
                )

                return

            # ----------------------------------------------------
            # Microflow
            # ----------------------------------------------------

            if self._is_microflow_type(
                node_type
            ):

                self._parse_microflow(
                    value
                )

            # ----------------------------------------------------
            # Page
            # ----------------------------------------------------

            elif self._is_page_type(
                node_type
            ):

                self._parse_page(
                    value
                )

            # ----------------------------------------------------
            # Module role
            # ----------------------------------------------------

            elif self._is_module_role_type(
                node_type
            ):

                self._parse_module_role(
                    value
                )

            # ----------------------------------------------------
            # Continue recursively.
            #
            # Entity was returned above because its children have
            # already been handled by _parse_entity().
            # ----------------------------------------------------

            for child in value.values():

                if isinstance(
                    child,
                    (dict, list),
                ):

                    self._walk_model(
                        child
                    )

        elif isinstance(
            value,
            list,
        ):

            for child in value:

                self._walk_model(
                    child
                )

    # ============================================================
    # MODULES
    # ============================================================

    def _parse_modules(
        self,
    ) -> None:

        nodes = self._find_nodes_by_exact_type(
            "Modules$Module"
        )

        for node in nodes:

            self._parse_module(
                node
            )

    def _parse_module(
        self,
        node: Dict[str, Any],
    ) -> Optional[Module]:

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        module_name = (
            qualified_name
            or
            name
        )

        if not module_name:

            return None

        if (
            module_name
            in
            self.modules_by_name
        ):

            return self.modules_by_name[
                module_name
            ]

        module = self._construct(
            Module,
            {
                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "entities":
                    [],

                "microflows":
                    [],

                "pages":
                    [],

                "roles":
                    [],
            },
        )

        self._ensure_list(
            module,
            "entities",
        )

        self._ensure_list(
            module,
            "microflows",
        )

        self._ensure_list(
            module,
            "pages",
        )

        self._ensure_list(
            module,
            "roles",
        )

        self.modules_by_name[
            module_name
        ] = module

        self.model.modules.append(
            module
        )

        return module

    def _ensure_module(
        self,
        module_name: str,
    ) -> Optional[Module]:

        if not module_name:

            return None

        if (
            module_name
            in
            self.modules_by_name
        ):

            return self.modules_by_name[
                module_name
            ]

        module = self._construct(
            Module,
            {
                "name":
                    module_name,

                "qualified_name":
                    module_name,

                "entities":
                    [],

                "microflows":
                    [],

                "pages":
                    [],

                "roles":
                    [],
            },
        )

        self._ensure_list(
            module,
            "entities",
        )

        self._ensure_list(
            module,
            "microflows",
        )

        self._ensure_list(
            module,
            "pages",
        )

        self._ensure_list(
            module,
            "roles",
        )

        self.modules_by_name[
            module_name
        ] = module

        self.model.modules.append(
            module
        )

        return module

    # ============================================================
    # ENTITY
    # ============================================================

    def _parse_entity(
        self,
        node: Dict[str, Any],
    ) -> Optional[Entity]:

        entity_id = str(
            node.get(
                "$ID",
                "",
            )
            or ""
        )

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        if not qualified_name:

            qualified_name = name

        if not name and not qualified_name:

            return None

        # --------------------------------------------------------
        # Duplicate entity protection
        # --------------------------------------------------------

        if (
            qualified_name
            in
            self.entities_by_name
        ):

            entity = (
                self.entities_by_name[
                    qualified_name
                ]
            )

            if entity_id:

                self.entities_by_id[
                    entity_id
                ] = entity

            return entity

        # --------------------------------------------------------
        # Module
        # --------------------------------------------------------

        module = (
            self._module_from_name(
                qualified_name
            )
        )

        # --------------------------------------------------------
        # Generalization
        # --------------------------------------------------------

        generalization = node.get(
            "generalization"
        )

        generalization_name = (
            self._reference_name(
                generalization
            )
        )

        persistable = True

        if isinstance(
            generalization,
            dict,
        ):

            generalization_type = str(
                generalization.get(
                    "$Type",
                    "",
                )
                or ""
            )

            if (
                generalization_type
                ==
                "DomainModels$NoGeneralization"
            ):

                if (
                    "persistable"
                    in
                    generalization
                ):

                    persistable = bool(
                        generalization.get(
                            "persistable"
                        )
                    )

        # --------------------------------------------------------
        # Construct entity
        # --------------------------------------------------------

        entity = self._construct(
            Entity,
            {
                "id":
                    entity_id,

                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "module":
                    module,

                "persistable":
                    persistable,

                "generalization":
                    generalization_name,

                "documentation":
                    str(
                        node.get(
                            "documentation",
                            "",
                        )
                        or ""
                    ),

                "attributes":
                    [],

                "associations":
                    [],

                "access_rules":
                    [],
            },
        )

        self._ensure_list(
            entity,
            "attributes",
        )

        self._ensure_list(
            entity,
            "associations",
        )

        self._ensure_list(
            entity,
            "access_rules",
        )

        # --------------------------------------------------------
        # Store entity
        # --------------------------------------------------------

        self.entities_by_name[
            qualified_name
        ] = entity

        if entity_id:

            self.entities_by_id[
                entity_id
            ] = entity

        self.model.entities.append(
            entity
        )

        # --------------------------------------------------------
        # Module relationship
        # --------------------------------------------------------

        module_object = (
            self._ensure_module(
                module
            )
        )

        if module_object:

            self._append_unique(
                module_object.entities,
                entity,
            )

        # ========================================================
        # ATTRIBUTES
        # ========================================================

        raw_attributes = node.get(
            "attributes",
            [],
        )

        if isinstance(
            raw_attributes,
            list,
        ):

            for raw_attribute in raw_attributes:

                if not isinstance(
                    raw_attribute,
                    dict,
                ):

                    continue

                attribute = (
                    self._parse_embedded_attribute(
                        raw_attribute,
                        entity,
                    )
                )

                if attribute is None:

                    continue

                self._append_unique(
                    entity.attributes,
                    attribute,
                )

                attribute_name = (
                    getattr(
                        attribute,
                        "qualified_name",
                        "",
                    )
                    or
                    getattr(
                        attribute,
                        "name",
                        "",
                    )
                )

                if (
                    attribute_name
                    and
                    attribute_name
                    not in
                    self.attributes_by_name
                ):

                    self.attributes_by_name[
                        attribute_name
                    ] = attribute

                    self.model.attributes.append(
                        attribute
                    )

        # ========================================================
        # ACCESS RULES
        # ========================================================

        raw_access_rules = node.get(
            "accessRules",
            [],
        )

        if isinstance(
            raw_access_rules,
            list,
        ):

            for raw_rule in raw_access_rules:

                if not isinstance(
                    raw_rule,
                    dict,
                ):

                    continue

                rule = (
                    self._parse_embedded_access_rule(
                        raw_rule,
                        entity,
                    )
                )

                if rule is None:

                    continue

                self._append_unique(
                    entity.access_rules,
                    rule,
                )

        return entity

    # ============================================================
    # ATTRIBUTE
    # ============================================================

    def _parse_embedded_attribute(
        self,
        node: Dict[str, Any],
        entity: Entity,
    ) -> Optional[Attribute]:

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        if not qualified_name:

            if (
                entity.qualified_name
                and
                name
            ):

                qualified_name = (
                    f"{entity.qualified_name}.{name}"
                )

        if not name and not qualified_name:

            return None

        attribute_type = (
            self._extract_attribute_type(
                node
            )
        )

        length = (
            self._extract_length(
                node
            )
        )

        attribute_id = str(
            node.get(
                "$ID",
                "",
            )
            or ""
        )

        attribute = self._construct(
            Attribute,
            {
                "id":
                    attribute_id,

                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "type":
                    attribute_type,

                "length":
                    length,

                "owner":
                    (
                        entity.qualified_name
                        or
                        entity.name
                    ),

                "entity":
                    (
                        entity.qualified_name
                        or
                        entity.name
                    ),

                "documentation":
                    str(
                        node.get(
                            "documentation",
                            "",
                        )
                        or ""
                    ),
            },
        )

        return attribute

    # ============================================================
    # ASSOCIATIONS
    # ============================================================

    def _parse_associations(
        self,
    ) -> None:

        """
        Mendix associations are standalone objects.

        Example:

            {
                "$Type": "DomainModels$Association",
                "$QualifiedName":
                    "OIDC.Token_ClientConfiguration",
                "parent":
                    "<ENTITY GUID>",
                "child":
                    "<ENTITY GUID>"
            }

        parent and child are entity $ID values.
        """

        nodes = (
            self._find_nodes_by_exact_type(
                "DomainModels$Association"
            )
        )

        for node in nodes:

            association_id = str(
                node.get(
                    "$ID",
                    "",
                )
                or ""
            )

            qualified_name = str(
                node.get(
                    "$QualifiedName",
                    "",
                )
                or ""
            )

            name = str(
                node.get(
                    "name",
                    "",
                )
                or ""
            )

            if not qualified_name:

                qualified_name = name

            if not qualified_name:

                continue

            if (
                qualified_name
                in
                self.associations_by_name
            ):

                continue

            parent_id = str(
                node.get(
                    "parent",
                    "",
                )
                or ""
            )

            child_id = str(
                node.get(
                    "child",
                    "",
                )
                or ""
            )

            association_type = str(
                node.get(
                    "type",
                    "",
                )
                or ""
            )

            owner = str(
                node.get(
                    "owner",
                    "",
                )
                or ""
            )

            documentation = str(
                node.get(
                    "documentation",
                    "",
                )
                or ""
            )

            # ----------------------------------------------------
            # Delete behavior
            # ----------------------------------------------------

            delete_behavior = (
                node.get(
                    "deleteBehavior"
                )
            )

            parent_delete_behavior = ""

            child_delete_behavior = ""

            if isinstance(
                delete_behavior,
                dict,
            ):

                parent_delete_behavior = str(
                    delete_behavior.get(
                        "parentDeleteBehavior",
                        "",
                    )
                    or ""
                )

                child_delete_behavior = str(
                    delete_behavior.get(
                        "childDeleteBehavior",
                        "",
                    )
                    or ""
                )

            # ----------------------------------------------------
            # Construct
            # ----------------------------------------------------

            association = self._construct(
                Association,
                {
                    "id":
                        association_id,

                    "name":
                        name,

                    "qualified_name":
                        qualified_name,

                    "type":
                        association_type,

                    "owner":
                        owner,

                    "parent_id":
                        parent_id,

                    "child_id":
                        child_id,

                    "parent":
                        parent_id,

                    "child":
                        child_id,

                    "parent_entity":
                        None,

                    "child_entity":
                        None,

                    "parent_name":
                        "",

                    "child_name":
                        "",

                    "parent_delete_behavior":
                        parent_delete_behavior,

                    "child_delete_behavior":
                        child_delete_behavior,

                    "documentation":
                        documentation,
                },
            )

            self.associations_by_name[
                qualified_name
            ] = association

            self.model.associations.append(
                association
            )

    # ============================================================
    # ACCESS RULE
    # ============================================================

    def _parse_embedded_access_rule(
        self,
        node: Dict[str, Any],
        entity: Entity,
    ) -> Optional[AccessRule]:

        rule_id = str(
            node.get(
                "$ID",
                "",
            )
            or ""
        )

        if (
            rule_id
            and
            rule_id
            in
            self.access_rules_by_id
        ):

            return self.access_rules_by_id[
                rule_id
            ]

        # --------------------------------------------------------
        # Roles
        # --------------------------------------------------------

        roles = []

        raw_roles = node.get(
            "moduleRoles",
            [],
        )

        if isinstance(
            raw_roles,
            list,
        ):

            for role in raw_roles:

                role_name = (
                    self._reference_name(
                        role
                    )
                )

                if role_name:

                    roles.append(
                        role_name
                    )

                    self._ensure_module_role(
                        role_name
                    )

        # --------------------------------------------------------
        # Member accesses
        # --------------------------------------------------------

        member_accesses = []

        raw_members = node.get(
            "memberAccesses",
            [],
        )

        if isinstance(
            raw_members,
            list,
        ):

            for raw_member in raw_members:

                if not isinstance(
                    raw_member,
                    dict,
                ):

                    continue

                member = (
                    self._parse_member_access(
                        raw_member
                    )
                )

                if member:

                    member_accesses.append(
                        member
                    )

        # --------------------------------------------------------
        # XPath
        # --------------------------------------------------------

        xpath_constraint = str(
            node.get(
                "xPathConstraint",
                "",
            )
            or ""
        )

        xpath_caption = str(
            node.get(
                "xPathConstraintCaption",
                "",
            )
            or ""
        )

        allow_create = bool(
            node.get(
                "allowCreate",
                False,
            )
        )

        allow_delete = bool(
            node.get(
                "allowDelete",
                False,
            )
        )

        default_member_access_rights = str(
            node.get(
                "defaultMemberAccessRights",
                "None",
            )
            or
            "None"
        )

        # --------------------------------------------------------
        # Construct rule
        # --------------------------------------------------------

        rule = self._construct(
            AccessRule,
            {
                "id":
                    rule_id,

                "roles":
                    roles,

                "module_roles":
                    roles,

                "member_accesses":
                    member_accesses,

                "allow_create":
                    allow_create,

                "allow_delete":
                    allow_delete,

                "default_member_access_rights":
                    default_member_access_rights,

                "xpath_constraint":
                    xpath_constraint,

                "xpath_constraint_caption":
                    xpath_caption,

                "entity":
                    (
                        entity.qualified_name
                        or
                        entity.name
                    ),

                "documentation":
                    str(
                        node.get(
                            "documentation",
                            "",
                        )
                        or
                        ""
                    ),
            },
        )

        # --------------------------------------------------------
        # Analyzer compatibility properties
        # --------------------------------------------------------

        self._set_if_possible(
            rule,
            "default_member_access",
            default_member_access_rights,
        )

        self._set_if_possible(
            rule,
            "has_xpath_constraint",
            bool(
                xpath_constraint.strip()
            ),
        )

        self._set_if_possible(
            rule,
            "has_write_access",
            self._member_access_has(
                member_accesses,
                "write",
            ),
        )

        self._set_if_possible(
            rule,
            "has_read_access",
            self._member_access_has(
                member_accesses,
                "read",
            ),
        )

        self._set_if_possible(
            rule,
            "has_read_write_access",
            self._member_access_has(
                member_accesses,
                "readwrite",
            ),
        )

        if rule_id:

            self.access_rules_by_id[
                rule_id
            ] = rule

        self.model.access_rules.append(
            rule
        )

        return rule

    # ============================================================
    # MEMBER ACCESS
    # ============================================================

    @staticmethod
    def _parse_member_access(
        node: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        attribute = str(
            node.get(
                "attribute",
                "",
            )
            or
            ""
        )

        association = str(
            node.get(
                "association",
                "",
            )
            or
            ""
        )

        access_rights = str(
            node.get(
                "accessRights",
                "None",
            )
            or
            "None"
        )

        return {
            "attribute":
                attribute,

            "association":
                association,

            "access_rights":
                access_rights,
        }

    # ============================================================
    # MICROFLOWS
    # ============================================================

    def _parse_microflow(
        self,
        node: Dict[str, Any],
    ) -> Optional[Microflow]:

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        if not qualified_name:

            qualified_name = name

        if not qualified_name:

            return None

        if (
            qualified_name
            in
            self.microflows_by_name
        ):

            return self.microflows_by_name[
                qualified_name
            ]

        module = (
            self._module_from_name(
                qualified_name
            )
        )

        apply_entity_access = (
            self._find_boolean(
                node,
                [
                    "applyEntityAccess",
                    "applyEntityAccessForMicroflows",
                ],
                True,
            )
        )

        allowed_roles = (
            self._find_string_list(
                node,
                [
                    "moduleRoles",
                    "allowedModuleRoles",
                    "allowedRoles",
                ],
            )
        )

        microflow = self._construct(
            Microflow,
            {
                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "module":
                    module,

                "apply_entity_access":
                    apply_entity_access,

                "allowed_module_roles":
                    allowed_roles,

                "bypasses_entity_access":
                    not apply_entity_access,
            },
        )

        self.microflows_by_name[
            qualified_name
        ] = microflow

        self.model.microflows.append(
            microflow
        )

        module_object = (
            self._ensure_module(
                module
            )
        )

        if module_object:

            self._append_unique(
                module_object.microflows,
                microflow,
            )

        return microflow

    # ============================================================
    # PAGES
    # ============================================================

    def _parse_page(
        self,
        node: Dict[str, Any],
    ) -> Optional[Page]:

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        if not qualified_name:

            qualified_name = name

        if not qualified_name:

            return None

        if (
            qualified_name
            in
            self.pages_by_name
        ):

            return self.pages_by_name[
                qualified_name
            ]

        module = (
            self._module_from_name(
                qualified_name
            )
        )

        allowed_roles = (
            self._find_string_list(
                node,
                [
                    "moduleRoles",
                    "allowedRoles",
                ],
            )
        )

        page = self._construct(
            Page,
            {
                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "module":
                    module,

                "allowed_roles":
                    allowed_roles,
            },
        )

        self.pages_by_name[
            qualified_name
        ] = page

        self.model.pages.append(
            page
        )

        module_object = (
            self._ensure_module(
                module
            )
        )

        if module_object:

            self._append_unique(
                module_object.pages,
                page,
            )

        return page

    # ============================================================
    # MODULE ROLES
    # ============================================================

    def _parse_module_role(
        self,
        node: Dict[str, Any],
    ) -> Optional[ModuleRole]:

        name = self._name(
            node
        )

        qualified_name = (
            self._qualified_name(
                node
            )
        )

        if not qualified_name:

            qualified_name = name

        if not qualified_name:

            return None

        return self._ensure_module_role(
            qualified_name
        )

    def _ensure_module_role(
        self,
        qualified_name: str,
    ) -> Optional[ModuleRole]:

        if not qualified_name:

            return None

        if (
            qualified_name
            in
            self.module_roles_by_name
        ):

            return self.module_roles_by_name[
                qualified_name
            ]

        name = (
            qualified_name.rsplit(
                ".",
                1,
            )[-1]
        )

        module = (
            self._module_from_name(
                qualified_name
            )
        )

        role = self._construct(
            ModuleRole,
            {
                "name":
                    name,

                "qualified_name":
                    qualified_name,

                "module":
                    module,
            },
        )

        self.module_roles_by_name[
            qualified_name
        ] = role

        self.model.module_roles.append(
            role
        )

        module_object = (
            self._ensure_module(
                module
            )
        )

        if module_object:

            self._append_unique(
                module_object.roles,
                role,
            )

        return role

    # ============================================================
    # REFERENCE RESOLUTION
    # ============================================================

    def _resolve_references(
        self,
    ) -> None:

        # ========================================================
        # ASSOCIATIONS
        # ========================================================

        for association in self.model.associations:

            parent_id = str(
                getattr(
                    association,
                    "parent_id",
                    "",
                )
                or
                ""
            )

            child_id = str(
                getattr(
                    association,
                    "child_id",
                    "",
                )
                or
                ""
            )

            parent_entity = (
                self.entities_by_id.get(
                    parent_id
                )
            )

            child_entity = (
                self.entities_by_id.get(
                    child_id
                )
            )

            # ----------------------------------------------------
            # Parent
            # ----------------------------------------------------

            self._set_if_possible(
                association,
                "parent_entity",
                parent_entity,
            )

            if parent_entity:

                parent_name = (
                    parent_entity.qualified_name
                    or
                    parent_entity.name
                )

                self._set_if_possible(
                    association,
                    "parent_name",
                    parent_name,
                )

                self._append_unique(
                    parent_entity.associations,
                    association,
                )

            # ----------------------------------------------------
            # Child
            # ----------------------------------------------------

            self._set_if_possible(
                association,
                "child_entity",
                child_entity,
            )

            if child_entity:

                child_name = (
                    child_entity.qualified_name
                    or
                    child_entity.name
                )

                self._set_if_possible(
                    association,
                    "child_name",
                    child_name,
                )

                self._append_unique(
                    child_entity.associations,
                    association,
                )

        # ========================================================
        # ATTRIBUTES
        # ========================================================

        for entity in self.model.entities:

            for attribute in entity.attributes:

                owner_name = (
                    entity.qualified_name
                    or
                    entity.name
                )

                self._set_if_possible(
                    attribute,
                    "entity",
                    owner_name,
                )

                self._set_if_possible(
                    attribute,
                    "owner",
                    owner_name,
                )

        # ========================================================
        # ACCESS RULES
        # ========================================================

        for entity in self.model.entities:

            for rule in entity.access_rules:

                self._set_if_possible(
                    rule,
                    "entity",
                    (
                        entity.qualified_name
                        or
                        entity.name
                    ),
                )

    # ============================================================
    # EXACT NODE SEARCH
    # ============================================================

    def _find_nodes_by_exact_type(
        self,
        node_type_to_find: str,
    ) -> List[Dict[str, Any]]:

        result = []

        def walk(
            value: Any,
        ):

            if isinstance(
                value,
                dict,
            ):

                node_type = str(
                    value.get(
                        "$Type",
                        "",
                    )
                    or
                    ""
                )

                if (
                    node_type
                    ==
                    node_type_to_find
                ):

                    result.append(
                        value
                    )

                for child in value.values():

                    if isinstance(
                        child,
                        (dict, list),
                    ):

                        walk(
                            child
                        )

            elif isinstance(
                value,
                list,
            ):

                for child in value:

                    walk(
                        child
                    )

        walk(
            self.data
        )

        return result

    # ============================================================
    # GENERAL NODE SEARCH
    # ============================================================

    def _find_nodes_by_type(
        self,
        suffix: str,
    ) -> List[Dict[str, Any]]:

        result = []

        def walk(
            value: Any,
        ):

            if isinstance(
                value,
                dict,
            ):

                node_type = str(
                    value.get(
                        "$Type",
                        "",
                    )
                    or
                    ""
                )

                if (
                    node_type == suffix
                    or
                    node_type.endswith(
                        suffix
                    )
                ):

                    result.append(
                        value
                    )

                for child in value.values():

                    if isinstance(
                        child,
                        (dict, list),
                    ):

                        walk(
                            child
                        )

            elif isinstance(
                value,
                list,
            ):

                for child in value:

                    walk(
                        child
                    )

        walk(
            self.data
        )

        return result

    # ============================================================
    # TYPE DETECTION
    # ============================================================

    @staticmethod
    def _is_microflow_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Microflows$Microflow"
            or
            node_type.endswith(
                "Microflows$Microflow"
            )
        )

    @staticmethod
    def _is_page_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Pages$Page"
            or
            node_type.endswith(
                "Pages$Page"
            )
        )

    @staticmethod
    def _is_module_role_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Security$ModuleRole"
            or
            node_type.endswith(
                "Security$ModuleRole"
            )
        )

    # ============================================================
    # NAME HELPERS
    # ============================================================

    @staticmethod
    def _name(
        node: Dict[str, Any],
    ) -> str:

        return str(
            node.get(
                "name",
                "",
            )
            or
            ""
        )

    @staticmethod
    def _qualified_name(
        node: Dict[str, Any],
    ) -> str:

        return str(
            node.get(
                "$QualifiedName",
                "",
            )
            or
            node.get(
                "qualifiedName",
                "",
            )
            or
            ""
        )

    @staticmethod
    def _module_from_name(
        qualified_name: str,
    ) -> str:

        if not qualified_name:

            return ""

        parts = (
            qualified_name.split(
                "."
            )
        )

        if len(parts) < 2:

            return ""

        return parts[0]

    # ============================================================
    # REFERENCE NAME
    # ============================================================

    @classmethod
    def _reference_name(
        cls,
        value: Any,
    ) -> str:

        if value is None:

            return ""

        if isinstance(
            value,
            str,
        ):

            return value

        if isinstance(
            value,
            dict,
        ):

            return str(
                value.get(
                    "$QualifiedName",
                    "",
                )
                or
                value.get(
                    "qualifiedName",
                    "",
                )
                or
                value.get(
                    "name",
                    "",
                )
                or
                value.get(
                    "$Ref",
                    "",
                )
                or
                ""
            )

        return str(
            value
        )

    # ============================================================
    # ATTRIBUTE TYPE
    # ============================================================

    @staticmethod
    def _extract_attribute_type(
        node: Dict[str, Any],
    ) -> str:

        attribute_type = node.get(
            "type"
        )

        if isinstance(
            attribute_type,
            dict,
        ):

            return str(
                attribute_type.get(
                    "$Type",
                    "",
                )
                or
                ""
            )

        return str(
            attribute_type
            or
            ""
        )

    @staticmethod
    def _extract_length(
        node: Dict[str, Any],
    ) -> Optional[int]:

        attribute_type = node.get(
            "type"
        )

        if not isinstance(
            attribute_type,
            dict,
        ):

            return None

        length = attribute_type.get(
            "length"
        )

        if length is None:

            return None

        try:

            return int(
                length
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

    # ============================================================
    # BOOLEAN
    # ============================================================

    @staticmethod
    def _find_boolean(
        node: Dict[str, Any],
        keys: List[str],
        default: bool,
    ) -> bool:

        for key in keys:

            if key in node:

                return bool(
                    node[key]
                )

        return default

    # ============================================================
    # STRING LIST
    # ============================================================

    @classmethod
    def _find_string_list(
        cls,
        node: Dict[str, Any],
        keys: List[str],
    ) -> List[str]:

        for key in keys:

            value = node.get(
                key
            )

            if not isinstance(
                value,
                list,
            ):

                continue

            result = []

            for item in value:

                reference = (
                    cls._reference_name(
                        item
                    )
                )

                if reference:

                    result.append(
                        reference
                    )

            return result

        return []

    # ============================================================
    # MEMBER ACCESS
    # ============================================================

    @staticmethod
    def _member_access_has(
        members: List[Dict[str, Any]],
        permission: str,
    ) -> bool:

        permission = (
            permission.lower()
        )

        for member in members:

            rights = str(
                member.get(
                    "access_rights",
                    "",
                )
                or
                ""
            ).lower()

            if permission in rights:

                return True

        return False

    # ============================================================
    # OBJECT CONSTRUCTION
    # ============================================================

    @staticmethod
    def _construct(
        cls,
        values: Dict[str, Any],
    ):

        """
        Construct model classes while remaining compatible with
        the current model.py implementation.

        First try normal keyword construction.

        If the dataclass/model does not accept those arguments,
        create the object and assign what it supports.
        """

        try:

            return cls(
                **values
            )

        except TypeError:

            try:

                obj = cls()

            except TypeError:

                obj = cls.__new__(
                    cls
                )

            for key, value in values.items():

                try:

                    setattr(
                        obj,
                        key,
                        value,
                    )

                except (
                    AttributeError,
                    TypeError,
                ):

                    pass

            return obj

    # ============================================================
    # SAFE SET
    # ============================================================

    @staticmethod
    def _set_if_possible(
        obj: Any,
        name: str,
        value: Any,
    ) -> None:

        try:

            setattr(
                obj,
                name,
                value,
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass

    # ============================================================
    # SAFE LIST
    # ============================================================

    @staticmethod
    def _ensure_list(
        obj: Any,
        name: str,
    ) -> None:

        current = getattr(
            obj,
            name,
            None,
        )

        if isinstance(
            current,
            list,
        ):

            return

        try:

            setattr(
                obj,
                name,
                [],
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass

    # ============================================================
    # UNIQUE APPEND
    # ============================================================

    @staticmethod
    def _append_unique(
        collection: list,
        value: Any,
    ) -> None:

        if value not in collection:

            collection.append(
                value
            )


# ================================================================
# BACKWARDS COMPATIBILITY
# ================================================================

Parser = MendixModelParser