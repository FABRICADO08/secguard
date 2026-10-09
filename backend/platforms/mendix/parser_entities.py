from __future__ import annotations

from typing import Any, Dict, Optional

from .model import Attribute, Entity


class ParserEntitiesMixin:
    def _parse_entity(self, node: Dict[str, Any]) -> Optional[Entity]:
        entity_id = str(node.get("$ID", "") or "")
        name = self._name(node)
        qualified_name = self._qualified_name(node) or name
        if not name and not qualified_name:
            return None

        entity = self.entities_by_name.get(qualified_name)
        if entity is not None:
            if entity_id:
                self.entities_by_id[entity_id] = entity
            return entity

        module = self._module_from_name(qualified_name)
        entity = self._create_entity(node, entity_id, name, qualified_name, module)
        self.entities_by_name[qualified_name] = entity
        if entity_id:
            self.entities_by_id[entity_id] = entity
        self.model.entities.append(entity)
        module_object = self._ensure_module(module)
        if module_object:
            self._append_unique(module_object.entities, entity)
        self._parse_entity_attributes(node, entity)
        self._parse_entity_access_rules(node, entity)
        return entity

    def _create_entity(
        self, node: Dict[str, Any], entity_id: str, name: str,
        qualified_name: str, module: str,
    ) -> Entity:
        generalization = node.get("generalization")
        generalization_name = self._reference_name(generalization)
        persistable = True
        if isinstance(generalization, dict) and generalization.get("$Type") == "DomainModels$NoGeneralization":
            if "persistable" in generalization:
                persistable = bool(generalization.get("persistable"))
        entity = self._construct(Entity, {
            "id": entity_id, "name": name, "qualified_name": qualified_name,
            "module": module, "persistable": persistable,
            "generalization": generalization_name,
            "documentation": str(node.get("documentation", "") or ""),
            "attributes": [], "associations": [], "access_rules": [],
        })
        for collection in ("attributes", "associations", "access_rules"):
            self._ensure_list(entity, collection)
        return entity

    def _parse_entity_attributes(self, node: Dict[str, Any], entity: Entity) -> None:
        attributes = node.get("attributes", [])
        if not isinstance(attributes, list):
            return
        for raw_attribute in attributes:
            if not isinstance(raw_attribute, dict):
                continue
            attribute = self._parse_embedded_attribute(raw_attribute, entity)
            if attribute is None:
                continue
            self._append_unique(entity.attributes, attribute)
            name = getattr(attribute, "qualified_name", "") or getattr(attribute, "name", "")
            if name and name not in self.attributes_by_name:
                self.attributes_by_name[name] = attribute
                self.model.attributes.append(attribute)

    def _parse_entity_access_rules(self, node: Dict[str, Any], entity: Entity) -> None:
        rules = node.get("accessRules", [])
        if not isinstance(rules, list):
            return
        for raw_rule in rules:
            if not isinstance(raw_rule, dict):
                continue
            rule = self._parse_embedded_access_rule(raw_rule, entity)
            if rule is not None:
                self._append_unique(entity.access_rules, rule)

    def _parse_embedded_attribute(
        self, node: Dict[str, Any], entity: Entity
    ) -> Optional[Attribute]:
        name = self._name(node)
        qualified_name = self._qualified_name(node)
        if not qualified_name and entity.qualified_name and name:
            qualified_name = f"{entity.qualified_name}.{name}"
        if not name and not qualified_name:
            return None
        owner = entity.qualified_name or entity.name
        return self._construct(Attribute, {
            "id": str(node.get("$ID", "") or ""),
            "name": name,
            "qualified_name": qualified_name,
            "type": self._extract_attribute_type(node),
            "length": self._extract_length(node),
            "owner": owner,
            "entity": owner,
            "documentation": str(node.get("documentation", "") or ""),
        })
