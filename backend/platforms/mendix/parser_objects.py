from __future__ import annotations

from typing import Any, Dict, Optional

from .model import Microflow, ModuleRole, Page


class ParserObjectsMixin:
    def _parse_microflow(self, node: Dict[str, Any]) -> Optional[Microflow]:
        details = self._module_resource_details(node, self.microflows_by_name)
        if details is None:
            return None
        name, qualified_name, module, existing = details
        if existing is not None:
            return existing
        apply_access = self._find_boolean(
            node, ["applyEntityAccess", "applyEntityAccessForMicroflows"], True
        )
        roles = self._find_string_list(
            node, ["moduleRoles", "allowedModuleRoles", "allowedRoles"]
        )
        microflow = self._construct(Microflow, {
            "name": name, "qualified_name": qualified_name, "module": module,
            "apply_entity_access": apply_access, "allowed_module_roles": roles,
            "bypasses_entity_access": not apply_access,
        })
        self._store_module_resource(
            self.microflows_by_name, "microflows", qualified_name, microflow, module
        )
        return microflow

    def _module_resource_details(self, node: Dict[str, Any], index: Dict[str, Any]):
        name = self._name(node)
        qualified_name = self._qualified_name(node) or name
        if not qualified_name:
            return None
        return name, qualified_name, self._module_from_name(qualified_name), index.get(qualified_name)

    def _store_module_resource(
        self, index: Dict[str, Any], collection: str, qualified_name: str,
        resource: Any, module: str,
    ) -> None:
        index[qualified_name] = resource
        getattr(self.model, collection).append(resource)
        module_object = self._ensure_module(module)
        if module_object:
            self._append_unique(getattr(module_object, collection), resource)

    def _parse_page(self, node: Dict[str, Any]) -> Optional[Page]:
        details = self._module_resource_details(node, self.pages_by_name)
        if details is None:
            return None
        name, qualified_name, module, existing = details
        if existing is not None:
            return existing
        roles = self._find_string_list(node, ["moduleRoles", "allowedRoles"])
        page = self._construct(Page, {
            "name": name, "qualified_name": qualified_name,
            "module": module, "allowed_roles": roles,
        })
        self._store_module_resource(
            self.pages_by_name, "pages", qualified_name, page, module
        )
        return page

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

    def _ensure_module_role(self, qualified_name: str) -> Optional[ModuleRole]:
        if not qualified_name:
            return None
        existing = self.module_roles_by_name.get(qualified_name)
        if existing is not None:
            return existing
        module = self._module_from_name(qualified_name)
        role = self._create_module_role(qualified_name)
        self.module_roles_by_name[qualified_name] = role
        self.model.module_roles.append(role)
        module_object = self._ensure_module(module)
        if module_object:
            self._append_unique(module_object.roles, role)
        return role

    def _create_module_role(self, qualified_name: str) -> ModuleRole:
        return self._construct(ModuleRole, {
            "name": qualified_name.rsplit(".", 1)[-1],
            "qualified_name": qualified_name,
            "module": self._module_from_name(qualified_name),
        })
