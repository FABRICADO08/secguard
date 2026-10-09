from __future__ import annotations

from typing import Any, Dict, Optional

from .model import Module


class ParserWalkerMixin:
    def _walk_model(self, value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                self._walk_model(child)
            return
        if not isinstance(value, dict):
            return

        node_type = str(value.get("$Type", "") or "")
        if node_type == "DomainModels$Entity":
            self._parse_entity(value)
            return
        if self._is_microflow_type(node_type):
            self._parse_microflow(value)
        elif self._is_page_type(node_type):
            self._parse_page(value)
        elif self._is_module_role_type(node_type):
            self._parse_module_role(value)
        self._walk_model_children(value)


    def _walk_model_children(self, node: Dict[str, Any]) -> None:
        for child in node.values():
            if isinstance(child, (dict, list)):
                self._walk_model(child)

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

    def _parse_module(self, node: Dict[str, Any]) -> Optional[Module]:
        name = self._name(node)
        qualified_name = self._qualified_name(node)
        module_name = qualified_name or name
        if not module_name:
            return None
        return self._get_or_create_module(module_name, name, qualified_name)

    def _get_or_create_module(
        self, module_name: str, name: str, qualified_name: str
    ) -> Module:
        existing = self.modules_by_name.get(module_name)
        if existing is not None:
            return existing
        module = self._construct(Module, {
            "name": name,
            "qualified_name": qualified_name,
            "entities": [], "microflows": [], "pages": [], "roles": [],
        })
        for collection in ("entities", "microflows", "pages", "roles"):
            self._ensure_list(module, collection)
        self.modules_by_name[module_name] = module
        self.model.modules.append(module)
        return module

    def _ensure_module(self, module_name: str) -> Optional[Module]:
        if not module_name:
            return None
        return self._get_or_create_module(module_name, module_name, module_name)
