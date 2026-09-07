from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from backend.config.settings import PROBE_TIMEOUT
from backend.discovery.crawler import is_same_origin
from backend.discovery.http import absolute_url, build_session

# Sitemaps can list tens of thousands of URLs; only the first entries are
# useful as attack surface and the rest would bloat the stored record.
MAX_SITEMAP_URLS = 200

MAX_SITEMAP_DOCUMENTS = 5

SITEMAP_LOCATION = re.compile(
    r"<loc>\s*([^<\s]+)\s*</loc>",
    re.IGNORECASE,
)

DEFAULT_SITEMAPS = ("/sitemap.xml", "/sitemap_index.xml")

# Path fragments that suggest a robots entry is hiding something rather
# than excluding crawl noise.
SENSITIVE_FRAGMENTS = (
    "admin",
    "backup",
    "config",
    "console",
    "credential",
    "database",
    "debug",
    "internal",
    "manage",
    "password",
    "private",
    "secret",
    "staging",
    "test",
    "upload",
    ".git",
    ".env",
    ".sql",
)


def _directive(line: str) -> tuple[str, str]:
    name, separator, value = line.partition(":")

    if not separator:
        return "", ""

    return name.strip().lower(), value.strip()


def parse_robots(text: str) -> dict[str, Any]:
    """Extract disallowed paths and declared sitemaps from a robots body."""

    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()

        if not line:
            continue

        name, value = _directive(line)

        if not value:
            continue

        if name == "disallow" and value not in disallowed:
            disallowed.append(value)

        elif name == "allow" and value not in allowed:
            allowed.append(value)

        elif name == "sitemap" and value not in sitemaps:
            sitemaps.append(value)

    return {
        "disallowed": disallowed,
        "allowed": allowed,
        "sitemaps": sitemaps,
    }


def sensitive_disallowed(paths: list[str]) -> list[str]:
    return [
        path
        for path in paths
        if any(fragment in path.lower() for fragment in SENSITIVE_FRAGMENTS)
    ]


def _fetch(url: str, session: requests.Session) -> tuple[int | None, str]:
    try:
        response = session.get(
            url,
            timeout=PROBE_TIMEOUT,
            allow_redirects=True,
        )

    except requests.RequestException:
        return None, ""

    return response.status_code, response.text or ""


def _looks_like_robots(body: str) -> bool:
    """A 200 that serves the SPA shell is not a robots file."""

    lowered = body.lower()

    if "<html" in lowered:
        return False

    return any(
        directive in lowered
        for directive in ("user-agent:", "disallow:", "allow:", "sitemap:")
    )


def collect_sitemap_urls(
    sitemap_urls: list[str],
    base_url: str,
    session: requests.Session,
) -> dict[str, Any]:
    """
    Read sitemap documents, following index documents one level deep.

    Only same-origin documents are read: a sitemap may reference another
    host, and fetching that would take the scan off the authorized target.
    """

    queue = [url for url in sitemap_urls if is_same_origin(base_url, url)]

    seen_documents: list[str] = []
    urls: list[str] = []

    while queue and len(seen_documents) < MAX_SITEMAP_DOCUMENTS:
        document = queue.pop(0)

        if document in seen_documents:
            continue

        seen_documents.append(document)

        status, body = _fetch(document, session)

        if status != 200 or not body:
            continue

        for location in SITEMAP_LOCATION.findall(body):
            absolute = urljoin(document, location)

            if not is_same_origin(base_url, absolute):
                continue

            if absolute.lower().endswith(".xml"):
                if absolute not in seen_documents and absolute not in queue:
                    queue.append(absolute)

                continue

            if absolute not in urls and len(urls) < MAX_SITEMAP_URLS:
                urls.append(absolute)

    return {
        "documents": seen_documents,
        "urls": urls,
    }


def discover_robots_and_sitemaps(base_url: str) -> dict[str, Any]:
    """
    Read `/robots.txt` and any sitemap it declares.

    Robots and sitemap entries are authoritative statements about paths the
    owner knows exist, so they are a better source of attack surface than
    crawling alone; disallowed entries in particular often name the areas
    the owner would rather keep quiet.
    """

    session = build_session()

    robots_url = absolute_url(base_url, "/robots.txt")

    status, body = _fetch(robots_url, session)

    found = status == 200 and _looks_like_robots(body)

    parsed = parse_robots(body) if found else {
        "disallowed": [],
        "allowed": [],
        "sitemaps": [],
    }

    declared = list(parsed["sitemaps"])

    for path in DEFAULT_SITEMAPS:
        candidate = absolute_url(base_url, path)

        if candidate not in declared:
            declared.append(candidate)

    sitemap = collect_sitemap_urls(declared, base_url, session)

    origin = urlparse(base_url)

    return {
        "robots": {
            "url": robots_url,
            "found": found,
            "status_code": status,
            "disallowed": parsed["disallowed"],
            "allowed": parsed["allowed"],
            "sensitive_disallowed": sensitive_disallowed(parsed["disallowed"]),
            "declared_sitemaps": parsed["sitemaps"],
        },
        "sitemap": {
            "documents": sitemap["documents"],
            "urls": sitemap["urls"],
            "url_count": len(sitemap["urls"]),
        },
        "disallowed_urls": [
            f"{origin.scheme}://{origin.netloc}{path}"
            for path in parsed["disallowed"]
            if path.startswith("/")
        ],
    }
