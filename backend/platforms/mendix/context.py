from __future__ import annotations

from typing import Any, Dict, List

from .model import MendixModel, Entity


class MendixSecurityContext:

    def __init__(
        self,
        model: MendixModel,
    ):
        self.model = model

    # ========================================================
    # ENTITY CONTEXT
    # ========================================================

    def entity_context(
        self,
        entity: Entity,
    ) -> Dict[str, Any]:

        return {
            "entity":
                entity.qualified_name
                or entity.name,

            "module":
                entity.module,

            "attributes":
                [
                    {
                        "name":
                            attribute.name,

                        "qualified_name":
                            attribute.qualified_name,

                        "type":
                            attribute.type,
                    }

                    for attribute
                    in entity.attributes
                ],

            "attribute_count":
                len(entity.attributes),

            "access_rule_count":
                len(entity.access_rules),

            "associations":
                [
                    {
                        "name":
                            association.name,

                        "qualified_name":
                            association.qualified_name,

                        "parent":
                            association.parent,

                        "child":
                            association.child,
                    }

                    for association
                    in entity.associations
                ],
        }

    # ========================================================
    # ALL ENTITY CONTEXTS
    # ========================================================

    def all_entities(
        self,
    ) -> List[Dict[str, Any]]:

        return [
            self.entity_context(
                entity
            )

            for entity
            in self.model.entities
        ]

    # ========================================================
    # ROLE ACCESS
    # ========================================================

    def role_access(
        self,
        entity: Entity,
    ) -> Dict[str, List[str]]:

        access = {}

        for rule in entity.access_rules:

            for role in rule.roles:

                if role not in access:

                    access[role] = []

                member_access = (
                    rule.default_member_access_rights
                    or ""
                )

                if member_access:

                    access[role].append(
                        member_access
                    )

                if rule.allow_create:

                    access[role].append(
                        "Create"
                    )

                if rule.allow_delete:

                    access[role].append(
                        "Delete"
                    )

        return access

    # ========================================================
    # SENSITIVE ATTRIBUTE SEARCH
    # ========================================================

    def find_attributes(
        self,
        keywords: List[str],
    ) -> List[Dict[str, Any]]:

        results = []

        normalized = [
            keyword.lower()
            for keyword in keywords
        ]

        for entity in self.model.entities:

            for attribute in entity.attributes:

                name = (
                    attribute.name.lower()
                )

                matched = [
                    keyword
                    for keyword
                    in normalized
                    if keyword in name
                ]

                if not matched:

                    continue

                results.append(
                    {
                        "entity":
                            entity.qualified_name
                            or entity.name,

                        "attribute":
                            attribute.name,

                        "qualified_name":
                            attribute.qualified_name,

                        "matched_keywords":
                            matched,
                    }
                )

        return results