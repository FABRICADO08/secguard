from typing import Any


class MendixAnalyzerChecks:
    """Entity and association checks used by the Mendix analyzer."""

    def _check_entity_access(self) -> None:
        for entity in self._entities():
            entity_name = self._qualified_name(entity)

            if not entity_name:
                continue

            categories = self._detect_sensitive_categories(entity)
            for rule in self._entity_access_rules(entity):
                finding = self._entity_access_finding(
                    entity_name,
                    categories,
                    rule,
                )
                if finding is not None:
                    self.findings.append(finding)

    def _entity_access_finding(self, entity_name, categories, rule):
        state = self._entity_access_state(categories, rule)

        if state is None:
            return None

        return self._format_entity_access_finding(
            entity_name,
            categories,
            rule,
            state,
        )

    def _entity_access_state(self, categories, rule):
        roles = self._role_names(rule)
        allow_create = self._allow_create(rule)
        allow_delete = self._allow_delete(rule)
        xpath = self._xpath(rule)
        member_accesses = self._member_accesses(rule)
        broad_member_access = self._has_broad_member_access(
            member_accesses,
            rule,
        )

        if not broad_member_access and not allow_delete and not allow_create:
            return None

        sensitive = bool(categories)
        severity, title = self._entity_access_severity(
            sensitive,
            allow_create,
            allow_delete,
            broad_member_access,
            xpath,
        )
        if severity is None:
            return None

        return {
            "roles": roles,
            "allow_create": allow_create,
            "allow_delete": allow_delete,
            "xpath": xpath,
            "member_accesses": member_accesses,
            "broad_member_access": broad_member_access,
            "sensitive": sensitive,
            "severity": severity,
            "title": title,
            "recommendation": self._entity_access_recommendation(
                categories,
                allow_create,
                allow_delete,
                broad_member_access,
                xpath,
            ),
        }

    def _format_entity_access_finding(
        self,
        entity_name,
        categories,
        rule,
        state,
    ):
        roles = state["roles"]
        allow_create = state["allow_create"]
        allow_delete = state["allow_delete"]
        xpath = state["xpath"]
        member_accesses = state["member_accesses"]
        broad_member_access = state["broad_member_access"]
        sensitive = state["sensitive"]
        return {
            "rule_id": "MXSEC-101",
            "severity": state["severity"],
            "title": state["title"],
            "entity": entity_name,
            "module": self._module_from_entity(entity_name),
            "roles": roles,
            "access": {
                "create": allow_create,
                "delete": allow_delete,
                "default_member_access": self._access_rights(rule),
                "member_accesses": [
                    self._member_access_to_dict(member)
                    for member in member_accesses
                ],
            },
            "xpath": xpath,
            "sensitive": sensitive,
            "sensitive_categories": sorted(categories),
            "evidence": {
                "create_allowed": allow_create,
                "delete_allowed": allow_delete,
                "broad_member_access": broad_member_access,
                "xpath_constraint_present": bool(xpath),
                "roles": roles,
            },
            "risk": self._risk_for_entity_access(
                sensitive=sensitive,
                allow_create=allow_create,
                allow_delete=allow_delete,
                broad_member_access=broad_member_access,
                xpath=xpath,
            ),
            "recommendation": state["recommendation"],
        }

    def _has_broad_member_access(self, member_accesses, rule) -> bool:
        for member in member_accesses:
            rights = self._normalise(
                self._get(
                    member,
                    "access_rights",
                    self._get(member, "accessRights", ""),
                )
            )
            if rights in {"readwrite", "write"}:
                return True

        default_access = self._normalise(self._access_rights(rule))
        return default_access in {"readwrite", "write"}

    @staticmethod
    def _entity_access_severity(
        sensitive: bool,
        allow_create: bool,
        allow_delete: bool,
        broad_member_access: bool,
        xpath: str,
    ) -> tuple[str | None, str]:
        if sensitive:
            return MendixAnalyzerChecks._sensitive_access_severity(
                allow_create,
                allow_delete,
                broad_member_access,
            )

        return MendixAnalyzerChecks._general_access_severity(
            allow_delete,
            broad_member_access,
            xpath,
        )

    @staticmethod
    def _sensitive_access_severity(
        allow_create: bool,
        allow_delete: bool,
        broad_member_access: bool,
    ) -> tuple[str | None, str]:
        if allow_delete:
            return "critical", "Sensitive entity allows deletion"
        if broad_member_access:
            return (
                "critical",
                "Sensitive entity has broad write access "
                "without row-level restriction",
            )
        if allow_create:
            return "medium", "Sensitive entity allows record creation"
        return None, ""

    @staticmethod
    def _general_access_severity(
        allow_delete: bool,
        broad_member_access: bool,
        xpath: str,
    ) -> tuple[str | None, str]:
        if allow_delete and not xpath:
            return (
                "high",
                "Entity has broad delete/write access "
                "without row-level restriction",
            )
        if broad_member_access and not xpath:
            return (
                "high",
                "Entity has broad write access "
                "without row-level restriction",
            )
        return None, ""

    def _entity_access_recommendation(
        self,
        categories,
        allow_create: bool,
        allow_delete: bool,
        broad_member_access: bool,
        xpath: str,
    ) -> str:
        parts = []
        if allow_delete:
            parts.append(
                "Restrict delete access to roles that explicitly require deletion."
            )
        if allow_create:
            parts.append("Review which roles genuinely require create access.")
        if broad_member_access:
            parts.append(
                "Replace broad ReadWrite access with the minimum required "
                "member permissions."
            )
        if not xpath:
            parts.append(
                "Consider an XPath constraint when users should only access "
                "records within their permitted business scope."
            )
        if categories:
            category_text = ", ".join(sorted(categories))
            parts.append(
                "Review sensitive data categories "
                f"({category_text}) and ensure each role has only the "
                "minimum required access."
            )
        return " ".join(parts)

    def _check_sensitive_entities(self) -> None:
        for entity in self._entities():
            entity_name = self._qualified_name(entity)
            if not entity_name:
                continue

            categories = self._detect_sensitive_categories(entity)
            if not categories:
                continue

            sensitive_attributes = self._sensitive_attributes(entity)
            if not self._entity_access_rules(entity):
                self.findings.append(
                    self._sensitive_entity_finding(
                        entity_name,
                        categories,
                        sensitive_attributes,
                    )
                )

    def _sensitive_entity_finding(
        self,
        entity_name: str,
        categories: set[str],
        sensitive_attributes: dict,
    ) -> dict:
        return {
            "rule_id": "MXSEC-102",
            "severity": "high",
            "title": "Sensitive entity has no explicit access rules",
            "entity": entity_name,
            "module": self._module_from_entity(entity_name),
            "roles": [],
            "access": {},
            "xpath": "",
            "sensitive": True,
            "sensitive_categories": sorted(categories),
            "attributes": list(sensitive_attributes.keys()),
            "evidence": {"access_rule_count": 0},
            "risk": (
                "The model contains an entity associated with sensitive "
                "information but no explicit entity access rules were detected."
            ),
            "recommendation": (
                "Define explicit entity access rules and verify that only the "
                "minimum required module roles can access the sensitive data."
            ),
        }

    def _check_sensitive_attributes(self) -> None:
        for entity in self._entities():
            entity_name = self._qualified_name(entity)
            sensitive_attributes = self._sensitive_attributes(entity)
            if not sensitive_attributes:
                continue

            rules = self._entity_access_rules(entity)
            for attribute_name, categories in sensitive_attributes.items():
                risky_roles = self._sensitive_attribute_roles(
                    attribute_name,
                    rules,
                )
                if risky_roles:
                    self.findings.append(
                        self._sensitive_attribute_finding(
                            entity_name,
                            attribute_name,
                            categories,
                            risky_roles,
                        )
                    )

    def _sensitive_attribute_roles(self, attribute_name, rules) -> list[str]:
        risky_roles = []
        for rule in rules:
            roles = self._role_names(rule)
            for member in self._member_accesses(rule):
                member_attribute = self._get(member, "attribute", "")
                if not member_attribute or member_attribute != attribute_name:
                    continue

                rights = self._normalise(
                    self._get(
                        member,
                        "access_rights",
                        self._get(member, "accessRights", ""),
                    )
                )
                if rights in {"readwrite", "write", "read", "readonly"}:
                    risky_roles.extend(roles)
        return sorted(set(risky_roles))

    def _sensitive_attribute_finding(
        self,
        entity_name: str,
        attribute_name: str,
        categories: set[str],
        risky_roles: list[str],
    ) -> dict[str, Any]:
        category_text = ", ".join(sorted(categories))
        return {
            "rule_id": "MXSEC-106",
            "severity": "critical",
            "title": "Sensitive attribute is accessible to application roles",
            "entity": entity_name,
            "module": self._module_from_entity(entity_name),
            "roles": risky_roles,
            "attributes": [
                {
                    "name": attribute_name,
                    "sensitive_categories": sorted(categories),
                }
            ],
            "access": {"roles_with_access": risky_roles},
            "xpath": "",
            "sensitive": True,
            "sensitive_categories": sorted(categories),
            "evidence": {
                "attribute": attribute_name,
                "categories": sorted(categories),
                "roles": risky_roles,
            },
            "risk": (
                f"The attribute '{attribute_name}' appears to contain "
                f"{category_text} information and is accessible through "
                "one or more module roles."
            ),
            "recommendation": (
                "Review whether every listed role needs access to this "
                "attribute. Remove unnecessary Read/Write permissions and "
                "apply least-privilege access."
            ),
        }

    def _check_associations(self) -> None:
        associations = self._get(self.model, "associations", []) or []
        for association in associations:
            name = (
                self._get(association, "qualified_name")
                or self._get(association, "name")
                or ""
            )
            if not name:
                continue

            parent_behavior, child_behavior = self._association_behaviors(
                association
            )
            if (
                parent_behavior in self._DANGEROUS_DELETE_BEHAVIORS
                or child_behavior in self._DANGEROUS_DELETE_BEHAVIORS
            ):
                self.findings.append(
                    self._association_finding(
                        name,
                        parent_behavior,
                        child_behavior,
                    )
                )

    _DANGEROUS_DELETE_BEHAVIORS = {
        "DeleteMeAndReferences",
        "DeleteMeButKeepReferences",
    }

    def _association_behaviors(self, association):
        behavior = (
            self._get(
                association,
                "delete_behavior",
                self._get(association, "deleteBehavior", None),
            )
            or association
        )
        parent_behavior = self._get(
            behavior,
            "parent_delete_behavior",
            self._get(behavior, "parentDeleteBehavior", ""),
        )
        child_behavior = self._get(
            behavior,
            "child_delete_behavior",
            self._get(behavior, "childDeleteBehavior", ""),
        )
        return parent_behavior, child_behavior

    @staticmethod
    def _association_finding(name, parent_behavior, child_behavior):
        return {
            "rule_id": "MXSEC-401",
            "severity": "medium",
            "title": "Association has cascading delete behaviour",
            "association": name,
            "roles": [],
            "access": {},
            "xpath": "",
            "sensitive": False,
            "sensitive_categories": [],
            "evidence": {
                "parent_delete_behavior": parent_behavior,
                "child_delete_behavior": child_behavior,
            },
            "risk": (
                "Deleting one object may cause related objects to be deleted "
                "or references to be altered automatically."
            ),
            "recommendation": (
                "Review the association delete behaviour and confirm that "
                "cascading deletion is required for the application's "
                "business logic."
            ),
        }


__all__ = ["MendixAnalyzerChecks"]
