import pytest

from tests.test_generic_rules import make_context, rule_ids, run


def with_csp(policy):
    return make_context(
        response={
            "headers": {
                "Content-Security-Policy": policy,
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            }
        }
    )


def test_unsafe_inline_script_source_is_reported():
    findings = run(
        with_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
    )

    assert "GEN-CSP-001" in rule_ids(findings)


def test_unsafe_eval_is_reported_as_high():
    findings = run(with_csp("script-src 'self' 'unsafe-eval'; frame-ancestors 'none'"))

    csp = [f for f in findings if f["rule_id"] == "GEN-CSP-001"]

    assert csp and csp[0]["severity"] == "high"


def test_nonce_neutralises_unsafe_inline():
    findings = run(
        with_csp(
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'nonce-abc123'; "
            "frame-ancestors 'none'"
        )
    )

    assert "GEN-CSP-001" not in rule_ids(findings)


def test_wildcard_script_source_is_reported():
    findings = run(with_csp("default-src 'self'; script-src *; frame-ancestors 'none'"))

    assert "GEN-CSP-002" in rule_ids(findings)


def test_wildcard_default_src_is_reported_once():
    findings = run(with_csp("default-src https:; frame-ancestors 'none'"))

    wildcard = [f for f in findings if f["rule_id"] == "GEN-CSP-002"]

    assert len(wildcard) == 1
    assert wildcard[0]["evidence"]["directive"] == "default-src"


def test_script_src_overrides_a_wildcard_default_src():
    findings = run(
        with_csp("default-src *; script-src 'self'; frame-ancestors 'none'")
    )

    assert "GEN-CSP-002" not in rule_ids(findings)


def test_missing_restrictive_directives_are_reported():
    findings = run(with_csp("script-src 'self'"))

    missing = [f for f in findings if f["rule_id"] == "GEN-CSP-003"]

    assert missing
    assert missing[0]["evidence"]["missing_directives"] == [
        "base-uri",
        "frame-ancestors",
        "object-src",
    ]


def test_default_src_satisfies_fallback_directives():
    findings = run(with_csp("default-src 'self'; frame-ancestors 'none'"))

    assert "GEN-CSP-003" not in rule_ids(findings)


def test_absent_csp_does_not_trigger_quality_rules():
    context = make_context(response={"headers": {"X-Content-Type-Options": "nosniff"}})

    reported = rule_ids(run(context))

    assert "GEN-HDR-001" in reported
    assert not reported & {"GEN-CSP-001", "GEN-CSP-002", "GEN-CSP-003"}


def test_null_cors_origin_is_reported():
    context = make_context(
        response={"headers": {"Access-Control-Allow-Origin": "null"}}
    )

    assert "GEN-CORS-001" in rule_ids(run(context))


def test_wildcard_origin_with_state_changing_methods_is_reported():
    context = make_context(
        response={
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE",
            }
        }
    )

    findings = run(context)

    unsafe = [f for f in findings if f["rule_id"] == "GEN-CORS-002"]

    assert unsafe
    assert unsafe[0]["evidence"]["unsafe_methods"] == ["delete"]


def test_safe_methods_on_wildcard_origin_are_not_reported():
    context = make_context(
        response={
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD",
            }
        }
    )

    assert "GEN-CORS-002" not in rule_ids(run(context))


def test_specific_origin_is_not_reported():
    context = make_context(
        response={
            "headers": {
                "Access-Control-Allow-Origin": "https://trusted.test",
                "Access-Control-Allow-Methods": "DELETE",
            }
        }
    )

    reported = rule_ids(run(context))

    assert not reported & {"GEN-CORS-001", "GEN-CORS-002", "GEN-HDR-007"}


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLX",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "sk_live_0123456789abcdef",
    ],
)
def test_client_side_secrets_are_reported(secret):
    context = make_context(
        response={"body": f"<html><script>var k = '{secret}';</script></html>"}
    )

    findings = [f for f in run(context) if f["rule_id"] == "GEN-JS-001"]

    assert findings
    assert secret not in str(findings[0]["evidence"])


def test_hardcoded_credential_assignment_is_reported():
    context = make_context(
        response={
            "body": (
                "<html><script>const config = "
                "{apiKey: 'S3cretValue0123456'};</script></html>"
            )
        }
    )

    assert "GEN-JS-001" in rule_ids(run(context))


def test_placeholder_credentials_are_ignored():
    context = make_context(
        response={
            "body": (
                "<html><script>const apiKey = "
                "'your-api-key-here';</script></html>"
            )
        }
    )

    assert "GEN-JS-001" not in rule_ids(run(context))


def test_secret_outside_a_script_block_is_ignored():
    context = make_context(
        response={"body": "<html><p>AKIAIOSFODNN7EXAMPLX</p></html>"}
    )

    assert "GEN-JS-001" not in rule_ids(run(context))


def test_source_map_reference_is_reported():
    context = make_context(
        response={"body": "<html>//# sourceMappingURL=/static/app.js.map</html>"}
    )

    findings = [f for f in run(context) if f["rule_id"] == "GEN-JS-002"]

    assert findings
    assert findings[0]["evidence"]["source_map"] == "/static/app.js.map"


def session_cookie(**overrides):
    cookie = {
        "name": "sessionid",
        "domain": "app.test",
        "path": "/",
        "secure": True,
        "http_only": True,
        "same_site": "Lax",
        "expires": None,
    }

    cookie.update(overrides)

    return cookie


def test_persistent_session_cookie_is_reported():
    context = make_context(
        response={"cookies": [session_cookie(expires=1893456000)]}
    )

    assert "GEN-SES-004" in rule_ids(run(context))


def test_persistent_non_session_cookie_is_ignored():
    context = make_context(
        response={
            "cookies": [session_cookie(name="locale", expires=1893456000)]
        }
    )

    assert "GEN-SES-004" not in rule_ids(run(context))


def test_cookie_scoped_to_parent_domain_is_reported():
    context = make_context(
        final_url="https://app.test.example/",
        response={"cookies": [session_cookie(domain=".test.example")]},
    )

    findings = [f for f in run(context) if f["rule_id"] == "GEN-SES-005"]

    assert findings
    assert findings[0]["severity"] == "medium"


def test_host_only_cookie_is_not_reported():
    context = make_context(
        final_url="https://app.test/",
        response={"cookies": [session_cookie(domain="app.test")]},
    )

    assert "GEN-SES-005" not in rule_ids(run(context))


def test_basic_authentication_over_https_is_reported():
    context = make_context(
        response={"headers": {"WWW-Authenticate": 'Basic realm="admin"'}}
    )

    findings = [f for f in run(context) if f["rule_id"] == "GEN-AUTH-004"]

    assert findings
    assert findings[0]["severity"] == "medium"


def test_basic_authentication_over_http_is_high():
    context = make_context(
        requested_url="http://app.test",
        final_url="http://app.test/",
        response={"headers": {"WWW-Authenticate": "Basic"}},
    )

    findings = [f for f in run(context) if f["rule_id"] == "GEN-AUTH-004"]

    assert findings
    assert findings[0]["severity"] == "high"


def test_bearer_challenge_is_not_reported():
    context = make_context(
        response={"headers": {"WWW-Authenticate": "Bearer realm=api"}}
    )

    assert "GEN-AUTH-004" not in rule_ids(run(context))
