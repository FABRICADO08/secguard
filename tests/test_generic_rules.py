import pytest

from backend.rules.base import ScanContext
from backend.rules.engine import RuleEngine, analyze, default_rules

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def make_context(**overrides):
    response = {
        "headers": dict(SECURE_HEADERS),
        "cookies": [],
        "body": "<html></html>",
        "http_redirect": {
            "tested": True,
            "redirects_to_https": True,
        },
    }

    response.update(overrides.pop("response", {}))

    return ScanContext(
        application_id="test-application",
        requested_url=overrides.pop("requested_url", "https://app.test"),
        final_url=overrides.pop("final_url", "https://app.test/"),
        response=response,
        attack_surface=overrides.pop("attack_surface", {}),
        **overrides,
    )


def rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def run(context):
    return RuleEngine(default_rules()).run(context)


def test_hardened_target_produces_no_findings():
    assert run(make_context()) == []


@pytest.mark.parametrize(
    "header,expected_rule",
    [
        ("Content-Security-Policy", "GEN-HDR-001"),
        ("Strict-Transport-Security", "GEN-HDR-002"),
        ("X-Content-Type-Options", "GEN-HDR-003"),
        ("Referrer-Policy", "GEN-HDR-005"),
        ("Permissions-Policy", "GEN-HDR-006"),
    ],
)
def test_missing_header_is_reported(header, expected_rule):
    headers = dict(SECURE_HEADERS)
    headers.pop(header)

    findings = run(make_context(response={"headers": headers}))

    assert expected_rule in rule_ids(findings)


def test_short_hsts_max_age_is_reported_as_low():
    headers = dict(SECURE_HEADERS)
    headers["Strict-Transport-Security"] = "max-age=600"

    findings = run(make_context(response={"headers": headers}))

    hsts = [f for f in findings if f["rule_id"] == "GEN-HDR-002"]

    assert hsts and hsts[0]["severity"] == "low"
    assert hsts[0]["evidence"]["max_age"] == 600


def test_clickjacking_protection_accepts_csp_frame_ancestors():
    headers = dict(SECURE_HEADERS)
    headers.pop("X-Frame-Options")

    assert "GEN-HDR-004" not in rule_ids(
        run(make_context(response={"headers": headers}))
    )

    headers["Content-Security-Policy"] = "default-src 'self'"

    assert "GEN-HDR-004" in rule_ids(
        run(make_context(response={"headers": headers}))
    )


def test_wildcard_cors_with_credentials_is_high():
    headers = dict(SECURE_HEADERS)
    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Credentials"] = "true"

    findings = run(make_context(response={"headers": headers}))

    cors = [f for f in findings if f["rule_id"] == "GEN-HDR-007"]

    assert cors and cors[0]["severity"] == "high"


def test_plain_http_target_is_reported():
    findings = run(
        make_context(
            requested_url="http://app.test",
            final_url="http://app.test/",
        )
    )

    assert "GEN-TLS-001" in rule_ids(findings)

    # HSTS is not expected on a plain HTTP response.
    assert "GEN-HDR-002" not in rule_ids(findings)


def test_missing_https_redirect_is_reported():
    findings = run(
        make_context(
            response={
                "http_redirect": {
                    "tested": True,
                    "redirects_to_https": False,
                    "http_url": "http://app.test/",
                    "status_code": 200,
                }
            }
        )
    )

    assert "GEN-TLS-002" in rule_ids(findings)


def test_mixed_content_is_reported():
    findings = run(
        make_context(
            attack_surface={
                "scripts": [
                    "http://cdn.test/analytics.js",
                    "https://cdn.test/app.js",
                ]
            }
        )
    )

    mixed = [f for f in findings if f["rule_id"] == "GEN-TLS-003"]

    assert mixed
    assert mixed[0]["evidence"]["insecure_script_count"] == 1


def test_server_banner_is_only_reported_with_a_version():
    headers = dict(SECURE_HEADERS)
    headers["Server"] = "nginx"

    assert "GEN-INF-001" not in rule_ids(
        run(make_context(response={"headers": headers}))
    )

    headers["Server"] = "nginx/1.18.0"

    assert "GEN-INF-001" in rule_ids(
        run(make_context(response={"headers": headers}))
    )


def test_directory_listing_is_reported():
    findings = run(
        make_context(response={"body": "<h1>Index of /uploads</h1>"})
    )

    assert "GEN-INF-002" in rule_ids(findings)


def test_insecure_session_cookie_flags():
    findings = run(
        make_context(
            response={
                "cookies": [
                    {
                        "name": "SESSIONID",
                        "secure": False,
                        "http_only": False,
                        "same_site": "",
                    }
                ]
            }
        )
    )

    assert {"GEN-SES-001", "GEN-SES-002", "GEN-SES-003"} <= rule_ids(findings)


def test_hardened_cookie_produces_no_session_findings():
    findings = run(
        make_context(
            response={
                "cookies": [
                    {
                        "name": "SESSIONID",
                        "secure": True,
                        "http_only": True,
                        "same_site": "Lax",
                    }
                ]
            }
        )
    )

    assert not {"GEN-SES-001", "GEN-SES-002", "GEN-SES-003"} & rule_ids(
        findings
    )


def test_credentials_over_http_and_missing_csrf():
    findings = run(
        make_context(
            attack_surface={
                "forms": [
                    {
                        "page": "http://app.test/login",
                        "action": "http://app.test/login",
                        "method": "POST",
                        "inputs": [
                            {"name": "username", "type": "text"},
                            {"name": "password", "type": "password"},
                        ],
                    }
                ]
            }
        )
    )

    assert {"GEN-AUTH-001", "GEN-AUTH-002"} <= rule_ids(findings)


@pytest.mark.parametrize(
    "autocomplete,reported",
    [
        ("", True),
        ("on", True),
        ("username", True),
        ("off", False),
        ("new-password", False),
        ("current-password", False),
    ],
)
def test_password_autocomplete_only_accepts_safe_values(
    autocomplete,
    reported,
):
    findings = run(
        make_context(
            attack_surface={
                "forms": [
                    {
                        "page": "https://app.test/login",
                        "action": "https://app.test/login",
                        "method": "POST",
                        "inputs": [
                            {
                                "name": "password",
                                "type": "password",
                                "autocomplete": autocomplete,
                            }
                        ],
                    }
                ]
            }
        )
    )

    assert ("GEN-AUTH-003" in rule_ids(findings)) is reported


def test_csrf_token_field_suppresses_the_finding():
    findings = run(
        make_context(
            attack_surface={
                "forms": [
                    {
                        "page": "https://app.test/profile",
                        "action": "https://app.test/profile",
                        "method": "POST",
                        "inputs": [
                            {"name": "csrf_token", "type": "hidden"},
                            {"name": "nickname", "type": "text"},
                        ],
                    }
                ]
            }
        )
    )

    assert "GEN-AUTH-002" not in rule_ids(findings)


def test_exposed_sensitive_path_uses_scanner_severity():
    findings = run(
        make_context(
            attack_surface={
                "exposed_paths": [
                    {
                        "url": "https://app.test/.env",
                        "path": "/.env",
                        "label": "Environment file",
                        "severity": "critical",
                        "confidence": "confirmed",
                        "status_code": 200,
                    }
                ]
            }
        )
    )

    exposure = [f for f in findings if f["rule_id"] == "GEN-CFG-001"]

    assert exposure and exposure[0]["severity"] == "critical"


def test_unprobed_api_paths_do_not_create_findings():
    findings = run(
        make_context(
            attack_surface={
                "potential_api_paths": [
                    {
                        "url": "https://app.test/swagger",
                        "path": "/swagger",
                        "documentation": True,
                        "probed": False,
                        "state": "not-probed",
                    }
                ]
            }
        )
    )

    assert not {"GEN-API-001", "GEN-API-002"} & rule_ids(findings)


def test_reachable_swagger_and_json_api_are_reported():
    findings = run(
        make_context(
            attack_surface={
                "potential_api_paths": [
                    {
                        "url": "https://app.test/swagger.json",
                        "path": "/swagger.json",
                        "documentation": True,
                        "probed": True,
                        "state": "accessible",
                        "status_code": 200,
                        "content_type": "application/json",
                        "body_preview": '{"openapi": "3.0.0"}',
                    },
                    {
                        "url": "https://app.test/api/v1",
                        "path": "/api/v1",
                        "documentation": False,
                        "probed": True,
                        "state": "accessible",
                        "status_code": 200,
                        "content_type": "application/json",
                        "body_preview": '{"users": []}',
                    },
                ]
            }
        )
    )

    assert {"GEN-API-001", "GEN-API-002"} <= rule_ids(findings)


def test_graphql_introspection_raises_severity():
    findings = run(
        make_context(
            attack_surface={
                "potential_api_paths": [
                    {
                        "url": "https://app.test/graphql",
                        "path": "/graphql",
                        "documentation": False,
                        "probed": True,
                        "state": "accessible",
                        "status_code": 200,
                        "content_type": "text/html",
                        "body_preview": "<html>graphiql</html>",
                    }
                ]
            }
        )
    )

    graphql = [f for f in findings if f["rule_id"] == "GEN-API-003"]

    assert graphql and graphql[0]["severity"] == "high"


def test_findings_are_sorted_by_severity():
    findings = run(
        make_context(
            requested_url="http://app.test",
            final_url="http://app.test/",
            response={"headers": {}},
        )
    )

    severities = [finding["severity"] for finding in findings]

    assert severities == sorted(
        severities,
        key=lambda value: -[
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        ].index(value),
    )


def test_engine_isolates_a_failing_rule():
    class BrokenRule:
        id = "BROKEN-001"

        def evaluate(self, context):
            raise RuntimeError("boom")

    engine = RuleEngine([BrokenRule(), *default_rules()])

    engine.run(make_context(response={"headers": {}}))

    assert engine.errors == [{"rule_id": "BROKEN-001", "error": "boom"}]


def test_analyze_reports_rule_count():
    result = analyze(make_context())

    assert result["rules_evaluated"] == len(default_rules())
    assert result["rule_errors"] == []
