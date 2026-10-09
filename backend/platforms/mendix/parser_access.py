from __future__ import annotations

from typing import Any, Dict, List, Optional

from .model import AccessRule, Association, Entity


class ParserAccessMixin:
    def _parse_associations(self) -> None:
        """Parse standalone Mendix associations after entities are indexed."""
        for node in self._find_nodes_by_exact_type("DomainModels$Association"):
            self._parse_association(node)

    def _parse_association(self, node: Dict[str, Any]) -> None:
        name = str(node.get("$QualifiedName", "") or node.get("name", "") or "")
        if not name or name in self.associations_by_name:
            return
        parent_behavior, child_behavior = self._association_delete_behaviors(node)
        values = {
            "id": str(node.get("$ID", "") or ""),
            "name": str(node.get("name", "") or ""),
            "qualified_name": name,
            "type": str(node.get("type", "") or ""),
            "owner": str(node.get("owner", "") or ""),
            "parent_id": str(node.get("parent", "") or ""),
            "child_id": str(node.get("child", "") or ""),
            "parent": str(node.get("parent", "") or ""),
            "child": str(node.get("child", "") or ""),
            "parent_entity": None, "child_entity": None,
            "parent_name": "", "child_name": "",
            "parent_delete_behavior": parent_behavior,
            "child_delete_behavior": child_behavior,
            "documentation": str(node.get("documentation", "") or ""),
        }
        association = self._construct(Association, values)
        self.associations_by_name[name] = association
        self.model.associations.append(association)

    @staticmethod
    def _association_delete_behaviors(node: Dict[str, Any]) -> tuple[str, str]:
        behavior = node.get("deleteBehavior")
        if not isinstance(behavior, dict):
            return "", ""
        return (
            str(behavior.get("parentDeleteBehavior", "") or ""),
            str(behavior.get("childDeleteBehavior", "") or ""),
        )

    def _parse_embedded_access_rule(
        self, node: Dict[str, Any], entity: Entity
    ) -> Optional[AccessRule]:
        rule_id = str(node.get("$ID", "") or "")
        if rule_id and rule_id in self.access_rules_by_id:
            return self.access_rules_by_id[rule_id]
        roles = self._access_rule_roles(node)
        members = self._access_rule_members(node)
        xpath = str(node.get("xPathConstraint", "") or "")
        xpath_caption = str(node.get("xPathConstraintCaption", "") or "")
        allow_create = bool(node.get("allowCreate", False))
        allow_delete = bool(node.get("allowDelete", False))
        default_rights = str(node.get("defaultMemberAccessRights", "None") or "None")
        rule = self._construct(AccessRule, {
            "id": rule_id, "roles": roles, "module_roles": roles,
            "member_accesses": members, "allow_create": allow_create,
            "allow_delete": allow_delete,
            "default_member_access_rights": default_rights,
            "xpath_constraint": xpath, "xpath_constraint_caption": xpath_caption,
            "entity": entity.qualified_name or entity.name,
            "documentation": str(node.get("documentation", "") or ""),
        })
        self._set_access_rule_flags(rule, members, xpath, default_rights)
        if rule_id:
            self.access_rules_by_id[rule_id] = rule
        self.model.access_rules.append(rule)
        return rule

    def _access_rule_roles(self, node: Dict[str, Any]) -> List[str]:
        raw_roles = node.get("moduleRoles", [])
        if not isinstance(raw_roles, list):
            return []
        roles = []
        for role in raw_roles:
            role_name = self._reference_name(role)
            if role_name:
                roles.append(role_name)
                self._ensure_module_role(role_name)
        return roles

    def _access_rule_members(self, node: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw_members = node.get("memberAccesses", [])
        if not isinstance(raw_members, list):
            return []
        return [
            member for raw in raw_members
            if isinstance(raw, dict)
            for member in [self._parse_member_access(raw)]
            if member
        ]

    def _set_access_rule_flags(
        self, rule: AccessRule, members: List[Dict[str, Any]],
        xpath: str, default_rights: str,
    ) -> None:
        self._set_if_possible(rule, "default_member_access", default_rights)
        self._set_if_possible(rule, "has_xpath_constraint", bool(xpath.strip()))
        self._set_if_possible(rule, "has_write_access", self._member_access_has(members, "write"))
        self._set_if_possible(rule, "has_read_access", self._member_access_has(members, "read"))
        self._set_if_possible(rule, "has_read_write_access", self._member_access_has(members, "readwrite"))

    @staticmethod
    def _parse_member_access(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return {
            "attribute": str(node.get("attribute", "") or ""),
            "association": str(node.get("association", "") or ""),
            "access_rights": str(node.get("accessRights", "None") or "None"),
        }

    def _resolve_member_access_attributes(self) -> None:
        for entity in self.model.entities:
            self._resolve_entity_member_access_attributes(entity)

    def _resolve_entity_member_access_attributes(self, entity: Entity) -> None:
        attributes_by_id = {
            str(getattr(attribute, "id", "") or ""): attribute
            for attribute in getattr(entity, "attributes", [])
        }
        for rule in getattr(entity, "access_rules", []):
            for member in getattr(rule, "member_accesses", []):
                if not isinstance(member, dict):
                    continue
                reference = str(member.get("attribute", "") or "")
                attribute = attributes_by_id.get(reference)
                if attribute is None:
                    continue
                member["attribute_id"] = reference
                member["attribute"] = attribute.qualified_name or attribute.name
