from backend.platforms.outsystems.analyzer import (
    OutSystemsSecurityAnalyzer,
)
from backend.platforms.outsystems.parser import OutSystemsModelParser


def parse(document):
    return OutSystemsModelParser(document).parse()


def test_pascal_case_keys_are_accepted():
    model = parse(
        {
            "Name": "Portal",
            "Modules": [
                {
                    "Name": "Core",
                    "Entities": [
                        {
                            "Name": "Customer",
                            "IsPublic": True,
                            "Attributes": [
                                {"Name": "Email", "DataType": "Email"}
                            ],
                        }
                    ],
                    "Screens": [{"Name": "Home", "Roles": ["User"]}],
                }
            ],
        }
    )

    assert model.name == "Portal"
    assert model.entities[0].qualified_name == "Core.Customer"
    assert model.entities[0].is_public is True
    assert model.screens[0].roles == ["User"]
    assert model.entities[0].attributes[0].entity == "Customer"


def test_roles_may_be_objects_or_strings():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "roles": [{"name": "Agent"}, "Customer"],
                    "screens": [{"name": "Home", "roles": [{"name": "Agent"}]}],
                }
            ]
        }
    )

    assert model.roles == ["Agent", "Customer"]
    assert model.screens[0].roles == ["Agent"]


def test_method_inherits_api_authentication_and_roles():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "exposedRestApis": [
                        {
                            "name": "Api",
                            "authentication": "Basic",
                            "roles": ["Agent"],
                            "methods": [
                                {"name": "List", "httpMethod": "GET"},
                                {
                                    "name": "Open",
                                    "authentication": "None",
                                    "roles": [],
                                },
                            ],
                        }
                    ],
                }
            ]
        }
    )

    inherited, overridden = model.rest_methods

    assert inherited.authentication == "Basic"
    assert inherited.roles == ["Agent"]
    assert overridden.authentication == "None"
    assert overridden.roles == ["Agent"]


def test_string_booleans_are_understood():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "entities": [
                        {
                            "name": "Customer",
                            "public": "true",
                            "exposeReadOnly": "false",
                        }
                    ],
                }
            ]
        }
    )

    assert model.entities[0].is_public is True
    assert model.entities[0].expose_read_only is False


def test_unknown_document_parses_to_an_empty_model():
    assert parse({"hello": "world"}).is_empty


def test_encrypted_and_non_sensitive_attributes_are_not_reported():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "entities": [
                        {
                            "name": "Customer",
                            "attributes": [
                                {"name": "Password", "isEncrypted": True},
                                {"name": "DisplayOrder"},
                            ],
                        }
                    ],
                }
            ]
        }
    )

    assert OutSystemsSecurityAnalyzer(model).analyze() == []


def test_anonymous_screen_with_roles_is_still_reported():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "screens": [
                        {"name": "Home", "anonymous": True, "roles": ["User"]}
                    ],
                }
            ]
        }
    )

    findings = OutSystemsSecurityAnalyzer(model).analyze()

    assert [finding["rule_id"] for finding in findings] == ["OSSEC-101"]


def test_site_property_without_a_default_value_is_not_reported():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "siteProperties": [
                        {"name": "ApiKey", "defaultValue": ""},
                        {"name": "PageSize", "defaultValue": "25"},
                    ],
                }
            ]
        }
    )

    assert OutSystemsSecurityAnalyzer(model).analyze() == []


def test_aggregate_query_with_inline_parameters_is_not_reported():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "queries": [
                        {
                            "name": "GetCustomers",
                            "kind": "Aggregate",
                            "expandInline": ["OrderBy"],
                        }
                    ],
                }
            ]
        }
    )

    assert OutSystemsSecurityAnalyzer(model).analyze() == []


def test_advanced_query_with_inline_parameters_is_reported():
    model = parse(
        {
            "modules": [
                {
                    "name": "Core",
                    "queries": [
                        {
                            "name": "SearchCustomers",
                            "kind": "Advanced SQL",
                            "expandInline": ["OrderBy"],
                        }
                    ],
                }
            ]
        }
    )

    findings = OutSystemsSecurityAnalyzer(model).analyze()

    assert [finding["rule_id"] for finding in findings] == ["OSSEC-106"]


def test_single_word_pascal_case_flags_are_honoured():
    model = parse(
        {
            "Modules": [
                {
                    "Name": "Core",
                    "Entities": [{"Name": "Customer", "Public": True}],
                    "Screens": [{"Name": "Login", "Anonymous": True}],
                }
            ]
        }
    )

    assert model.entities[0].is_public is True
    assert model.screens[0].is_anonymous is True

    findings = OutSystemsSecurityAnalyzer(model).analyze()

    assert {finding["rule_id"] for finding in findings} == {
        "OSSEC-101",
        "OSSEC-103",
    }
