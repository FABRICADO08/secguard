from __future__ import annotations

from typing import Any, Dict, List

from .model import Association, Entity


class ParserResolutionMixin:
    def _resolve_references(self) -> None:
        self._resolve_member_access_attributes()
        self._resolve_associations()
        self._resolve_attribute_owners()
        self._resolve_access_rule_owners()

    def _resolve_associations(self) -> None:
        for association in self.model.associations:
            self._resolve_association(association)

    def _resolve_association(self, association: Association) -> None:
        parent_id = str(getattr(association, "parent_id", "") or "")
        child_id = str(getattr(association, "child_id", "") or "")
        parent = self.entities_by_id.get(parent_id)
        child = self.entities_by_id.get(child_id)
        self._set_if_possible(association, "parent_entity", parent)
        self._set_if_possible(association, "child_entity", child)
        if parent:
            self._set_association_entity(association, "parent", parent)
        if child:
            self._set_association_entity(association, "child", child)

    def _set_association_entity(self, association: Association, side: str, entity: Entity) -> None:
        name = entity.qualified_name or entity.name
        self._set_if_possible(association, f"{side}_name", name)
        self._append_unique(entity.associations, association)

    def _resolve_attribute_owners(self) -> None:
        for entity in self.model.entities:
            owner = entity.qualified_name or entity.name
            for attribute in entity.attributes:
                self._set_if_possible(attribute, "entity", owner)
                self._set_if_possible(attribute, "owner", owner)

    def _resolve_access_rule_owners(self) -> None:
        for entity in self.model.entities:
            owner = entity.qualified_name or entity.name
            for rule in entity.access_rules:
                self._set_if_possible(rule, "entity", owner)

    def _find_nodes_by_exact_type(self, node_type_to_find: str) -> List[Dict[str, Any]]:
        return [
            node for node in self._iter_model_nodes(self.data)
            if str(node.get("$Type", "") or "") == node_type_to_find
        ]

    def _iter_model_nodes(self, value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                if isinstance(child, (dict, list)):
                    yield from self._iter_model_nodes(child)
        elif isinstance(value, list):
            for child in value:
                yield from self._iter_model_nodes(child)

    def _find_nodes_by_type(self, suffix: str) -> List[Dict[str, Any]]:
        return [
            node for node in self._iter_model_nodes(self.data)
            if (node_type := str(node.get("$Type", "") or "")) == suffix
            or node_type.endswith(suffix)
        ]
