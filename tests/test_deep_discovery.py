from __future__ import annotations

import pytest
import requests

from backend.discovery import reflection, robots, scripts
from tests.test_generic_rules import make_context, rule_ids, run

ROBOTS_BODY = """
# comment
User-agent: *
Disallow: /admin/
Disallow: /assets/img/
Allow: /public/
Sitemap: https://app.test/sitemap.xml
"""

SITEMAP_INDEX = """<?xml version="1.0"?>
<sitemapindex>
  <sitemap><loc>https://app.test/sitemap-pages.xml</loc></sitemap>
</sitemapindex>
"""

SITEMAP_PAGES = """<?xml version="1.0"?>
<urlset>
  <url><loc>https://app.test/account</loc></url>
  <url><loc>https://other.test/leaked</loc></url>
</urlset>
"""


class FakeResponse:
    def __init__(self, status_code=200, text="", url=""):
        self.status_code = status_code
        self.text = text
        self.url = url


class FakeSession:
    def __init__(self, pages):
        self.pages = pages
        self.requested: list[str] = []

    def get(self, url, **kwargs):
        self.requested.append(url)

        if url not in self.pages:
            return FakeResponse(404, "not found", url)

        return FakeResponse(200, self.pages[url], url)


@pytest.fixture
def fake_network(monkeypatch):
    def install(pages, module):
        session = FakeSession(pages)

        monkeypatch.setattr(module, "build_session", lambda: session)

        return session

    return install


# ------------------------------------------------------------------
# robots.txt and sitemaps
# ------------------------------------------------------------------


def test_robots_directives_are_parsed():
    parsed = robots.parse_robots(ROBOTS_BODY)

    assert parsed["disallowed"] == ["/admin/", "/assets/img/"]
    assert parsed["allowed"] == ["/public/"]
    assert parsed["sitemaps"] == ["https://app.test/sitemap.xml"]


def test_only_sensitive_disallowed_paths_are_flagged():
    assert robots.sensitive_disallowed(
        ["/admin/", "/assets/img/", "/.git/"]
    ) == ["/admin/", "/.git/"]


def test_html_response_is_not_treated_as_robots(fake_network):
    fake_network(
        {"https://app.test/robots.txt": "<html><body>Not found</body></html>"},
        robots,
    )

    result = robots.discover_robots_and_sitemaps("https://app.test")

    assert result["robots"]["found"] is False
    assert result["robots"]["disallowed"] == []


def test_sitemap_index_is_followed_and_foreign_urls_dropped(fake_network):
    fake_network(
        {
            "https://app.test/robots.txt": ROBOTS_BODY,
            "https://app.test/sitemap.xml": SITEMAP_INDEX,
            "https://app.test/sitemap-pages.xml": SITEMAP_PAGES,
        },
        robots,
    )

    result = robots.discover_robots_and_sitemaps("https://app.test")

    assert result["robots"]["found"] is True
    assert result["sitemap"]["urls"] == ["https://app.test/account"]
    assert result["disallowed_urls"] == [
        "https://app.test/admin/",
        "https://app.test/assets/img/",
    ]


def test_sitemaps_on_other_hosts_are_not_fetched(fake_network):
    session = fake_network(
        {"https://app.test/robots.txt": "Sitemap: https://other.test/sitemap.xml"},
        robots,
    )

    robots.discover_robots_and_sitemaps("https://app.test")

    assert "https://other.test/sitemap.xml" not in session.requested


# ------------------------------------------------------------------
# Script analysis
# ------------------------------------------------------------------


def test_endpoints_are_extracted_from_javascript():
    source = """
        fetch("/api/v1/orders");
        axios.post("/api/v1/orders/create", body);
        const css = "/static/app.css";
        const cls = "col-md-6";
    """

    found = {entry["path"]: entry["method"] for entry in scripts.extract_endpoints(source)}

    assert found["/api/v1/orders"] == ""
    assert found["/api/v1/orders/create"] == "POST"
    assert "/static/app.css" not in found
    assert "col-md-6" not in found


def test_script_secrets_are_redacted():
    found = scripts.find_secrets('const k = "AKIAIOSFODNN7REALKEY";')

    assert found == [
        {"kind": "AWS access key id", "match": "AKIA...EY"}
    ]


def test_placeholder_values_are_not_reported_as_secrets():
    assert scripts.find_secrets('apiKey = "your_api_key_here"') == []


def test_only_same_origin_scripts_are_fetched(monkeypatch):
    fetched: list[str] = []

    def fake_fetch(url, session):
        fetched.append(url)

        return 200, 'fetch("/api/me");'

    monkeypatch.setattr(scripts, "build_session", lambda: object())
    monkeypatch.setattr(scripts, "_fetch_script", fake_fetch)

    result = scripts.analyze_scripts(
        [
            "https://app.test/static/app.js",
            "https://cdn.other.test/lib.js",
        ],
        "https://app.test",
    )

    assert fetched == ["https://app.test/static/app.js"]
    assert result["endpoints"][0]["url"] == "https://app.test/api/me"
    assert result["endpoints"][0]["discovered_by"] == "javascript"


# ------------------------------------------------------------------
# Reflected input probes
# ------------------------------------------------------------------


def test_only_get_parameters_are_probed():
    targets = reflection.probe_targets(
        [
            {
                "action": "https://app.test/search",
                "method": "GET",
                "inputs": [
                    {"name": "q", "type": "text"},
                    {"name": "go", "type": "submit"},
                ],
            },
            {
                "action": "https://app.test/login",
                "method": "POST",
                "inputs": [{"name": "username", "type": "text"}],
            },
        ],
        ["https://app.test/list?page=2", "https://other.test/x?y=1"],
        "https://app.test",
    )

    assert [(t["url"].split("?")[0], t["parameter"]) for t in targets] == [
        ("https://app.test/search", "q"),
        ("https://app.test/list", "page"),
    ]


@pytest.mark.parametrize(
    "template,expected",
    [
        ("<p>{payload}</p>", "raw"),
        ("<p>&quot;&#x27;&lt;&gt;{marker}</p>", "escaped"),
        ("<p>{marker}</p>", "encoded"),
        ("<p>nothing</p>", "none"),
    ],
)
def test_reflection_context_is_classified(template, expected):
    marker = "sgpdeadbeef"
    payload = f"{reflection.MARKER_CHARS}{marker}"

    body = template.format(payload=payload, marker=marker)

    assert reflection.reflection_context(body, payload, marker) == expected


def test_reflected_parameter_is_recorded(monkeypatch):
    class EchoSession:
        def get(self, url, **kwargs):
            value = url.split("q=", 1)[1]

            return FakeResponse(
                200,
                f"<p>{requests.utils.unquote(value)}</p>",
                url,
            )

    monkeypatch.setattr(reflection, "build_session", EchoSession)

    result = reflection.probe_reflection(
        [
            {
                "action": "https://app.test/search",
                "method": "GET",
                "inputs": [{"name": "q", "type": "text"}],
            }
        ],
        [],
        "https://app.test",
    )

    assert result["probe_count"] == 1
    assert result["reflected"][0]["context"] == "raw"
    assert result["reflected"][0]["parameter"] == "q"


def test_failed_probe_is_skipped(monkeypatch):
    class BrokenSession:
        def get(self, url, **kwargs):
            raise requests.ConnectionError("refused")

    monkeypatch.setattr(reflection, "build_session", BrokenSession)

    result = reflection.probe_reflection(
        [
            {
                "action": "https://app.test/search",
                "method": "GET",
                "inputs": [{"name": "q", "type": "text"}],
            }
        ],
        [],
        "https://app.test",
    )

    assert result == {"probes": [], "reflected": [], "probe_count": 0}


# ------------------------------------------------------------------
# Rules over the deeper surface
# ------------------------------------------------------------------


def test_sensitive_robots_paths_are_reported():
    findings = run(
        make_context(
            attack_surface={
                "robots": {
                    "url": "https://app.test/robots.txt",
                    "sensitive_disallowed": ["/admin/"],
                }
            }
        )
    )

    assert "GEN-INF-004" in rule_ids(findings)


def test_harmless_robots_paths_are_not_reported():
    findings = run(
        make_context(
            attack_surface={
                "robots": {"disallowed": ["/assets/"], "sensitive_disallowed": []}
            }
        )
    )

    assert "GEN-INF-004" not in rule_ids(findings)


def test_secret_in_served_script_is_reported():
    findings = run(
        make_context(
            attack_surface={
                "script_analysis": {
                    "scripts": [
                        {
                            "url": "https://app.test/static/app.js",
                            "secrets": [
                                {"kind": "Stripe secret key", "match": "sk_l...23"}
                            ],
                            "source_maps": ["/static/app.js.map"],
                        }
                    ]
                }
            }
        )
    )

    reported = [f for f in findings if f["rule_id"] == "GEN-JS-003"]

    assert reported[0]["location"] == "https://app.test/static/app.js"
    assert reported[0]["evidence"]["match"] == "sk_l...23"
    assert "GEN-JS-004" in rule_ids(findings)


def test_only_raw_reflection_is_reported():
    findings = run(
        make_context(
            attack_surface={
                "reflection": {
                    "reflected": [
                        {
                            "url": "https://app.test/search",
                            "parameter": "q",
                            "context": "escaped",
                        }
                    ]
                }
            }
        )
    )

    assert "GEN-INP-001" not in rule_ids(findings)


def test_raw_reflection_is_reported_as_tentative():
    findings = run(
        make_context(
            attack_surface={
                "reflection": {
                    "reflected": [
                        {
                            "url": "https://app.test/search",
                            "parameter": "q",
                            "source": "form",
                            "context": "raw",
                        }
                    ]
                }
            }
        )
    )

    reported = [f for f in findings if f["rule_id"] == "GEN-INP-001"]

    assert reported and reported[0]["confidence"] == "tentative"
    assert reported[0]["title"] == "Parameter 'q' is reflected unescaped"
