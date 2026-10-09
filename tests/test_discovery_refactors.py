from pathlib import Path

from backend.discovery import crawler, endpoints, technology


class FakeResponse:
    def __init__(self, url, text, content_type="text/html"):
        self.url = url
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": content_type}


class FakeSession:
    def get(self, url, **kwargs):
        pages = {
            "https://app.test": (
                '<a href="/api/orders#top">orders</a>'
                '<a href="https://other.test/out">external</a>'
                '<form action="/search" method="post">'
                '<input name="q" type="text"></form>'
                '<script src="/app.js"></script>'
            ),
            "https://app.test/api/orders": "<p>orders</p>",
        }
        return FakeResponse(url, pages[url])


def test_crawl_collects_same_origin_links_forms_and_scripts(monkeypatch):
    monkeypatch.setattr(crawler, "build_session", FakeSession)

    result = crawler.crawl("https://app.test/", max_pages=2)

    assert result["pages_scanned"] == 2
    assert result["links"] == ["https://app.test/api/orders"]
    assert result["forms"][0]["action"] == "https://app.test/search"
    assert result["forms"][0]["method"] == "POST"
    assert result["scripts"] == ["https://app.test/app.js"]


def test_endpoint_discovery_deduplicates_form_and_link_targets():
    found = endpoints.discover_endpoints(
        ["https://app.test/api/orders"],
        [
            {
                "action": "https://app.test/api/orders",
                "method": "get",
            },
            {
                "action": "https://app.test/search",
                "method": "post",
            },
        ],
    )

    assert [(item["path"], item["method"], item["type"]) for item in found] == [
        ("/api/orders", "GET", "api"),
        ("/search", "POST", "form"),
    ]


def test_technology_detection_preserves_platform_and_header_evidence():
    found = technology.detect_technologies(
        {
            "body": "<html>mendix react ng-version express</html>",
            "headers": {
                "Server": "nginx",
                "X-Powered-By": "Express",
            },
        }
    )

    assert [(item["name"], item["category"]) for item in found] == [
        ("Mendix", "Platform"),
        ("React", "Frontend"),
        ("Angular", "Frontend"),
        ("Node.js", "Backend"),
        ("nginx", "Server"),
    ]


def test_runtime_dependencies_are_exactly_pinned():
    requirements = (
        Path(__file__).resolve().parents[1] / "requirements.txt"
    ).read_text(encoding="utf-8")

    for package in ("Flask==3.1.3", "requests==2.34.2", "beautifulsoup4==4.15.0"):
        assert package in requirements.splitlines()
