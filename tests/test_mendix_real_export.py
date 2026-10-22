"""Exports in the shape `mx dump-mpr` produces for Mendix 10/11 projects."""

import json

from backend.platforms.mendix.parser import MendixModelParser
from backend.repository.mendix import analyse_mendix


def _module(name, app_store=False):
    return {"$Type": "Projects$Module", "$ID": f"module-{name}", "name": name, "fromAppStore": app_store}


def _page(qualified_name, roles):
    return {
        "$Type": "Pages$Page",
        "$QualifiedName": qualified_name,
        "name": qualified_name.split(".")[-1],
        "allowedRoles": roles,
    }


def _session_entity():
    return {
        "$Type": "DomainModels$DomainModel",
        "entities": [{
            "$Type": "DomainModels$Entity",
            "$ID": "entity-session",
            "$QualifiedName": "System.Session",
            "name": "Session",
            "attributes": [],
            "accessRules": [{
                "$Type": "DomainModels$AccessRule",
                "$ID": "rule-session",
                "moduleRoles": ["System.User"],
                "allowCreate": False,
                "allowDelete": True,
                "defaultMemberAccessRights": "None",
                "xPathConstraint": "",
            }],
        }],
    }


EXPORT = {
    "units": [
        _module("Shop"),
        _module("System"),
        {"$Type": "Security$ModuleSecurity", "moduleRoles": [
            {"$Type": "Security$ModuleRole", "$ID": "role-user", "$QualifiedName": "Shop.User", "name": "User"},
            {"$Type": "Security$ModuleRole", "$ID": "role-system", "$QualifiedName": "System.User", "name": "User"},
        ]},
        _page("Shop.Home", ["Shop.User"]),
        _page("Shop.Orders", ["Shop.User"]),
        {
            "$Type": "Microflows$Microflow",
            "$QualifiedName": "Shop.ACT_Order",
            "name": "ACT_Order",
            "applyEntityAccess": False,
            "allowedModuleRoles": ["Shop.User"],
        },
        _session_entity(),
    ]
}


def test_pages_microflows_and_modules_of_a_real_export_are_parsed():
    model = MendixModelParser(EXPORT).parse()

    assert {page.qualified_name: page.allowed_module_roles for page in model.pages} == {
        "Shop.Home": ["Shop.User"],
        "Shop.Orders": ["Shop.User"],
    }
    assert [flow.allowed_module_roles for flow in model.microflows] == [["Shop.User"]]
    assert model.microflows[0].bypasses_entity_access
    assert {"Shop", "System"} <= {module.name for module in model.modules}


def test_platform_system_module_findings_are_left_out(tmp_path):
    (tmp_path / "App.mpr").write_bytes(b"")
    export = tmp_path / "App.mpr.json"
    export.write_text(json.dumps(EXPORT), encoding="utf-8")

    summary, findings = analyse_mendix(tmp_path, export)

    assert summary["analyzed"] is True
    assert not [item for item in findings if "System." in item["title"]]
