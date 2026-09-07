from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from backend.config.settings import PROBE_TIMEOUT
from backend.discovery.crawler import is_same_origin
from backend.discovery.http import build_session
from backend.rules.generic.clientside import (
    SECRET_PATTERNS,
    SOURCE_MAP,
    is_placeholder,
    redact,
)

MAX_SCRIPTS = 15

# Bundles are routinely megabytes; reading the whole file buys little and
# costs a lot of memory, so each script is truncated.
MAX_SCRIPT_BYTES = 512_000

MAX_ENDPOINTS_PER_SCRIPT = 50

# Quoted absolute paths ("/api/users") and calls that carry an explicit
# URL. Bare relative strings are excluded: they collide with CSS classes,
# selectors and translation keys.
PATH_LITERAL = re.compile(r"""["'`](/[A-Za-z0-9_\-./{}$:]{2,120})["'`]""")

FETCH_CALL = re.compile(
    r"""(?:fetch|axios(?:\.[a-z]+)?|\.(?:get|post|put|patch|delete)|open)"""
    r"""\s*\(\s*["'`]([^"'`]{2,200})["'`]""",
    re.IGNORECASE,
)

METHOD_CALL = re.compile(
    r"""(?:axios\.|\.)(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]{2,200})["'`]""",
    re.IGNORECASE,
)

# Paths that are assets rather than endpoints.
ASSET_SUFFIXES = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webp",
)


def _is_endpoint(path: str) -> bool:
    if not path.startswith("/") or path.startswith("//"):
        return False

    lowered = path.split("?", 1)[0].lower()

    return not lowered.endswith(ASSET_SUFFIXES)


def extract_endpoints(source: str) -> list[dict[str, str]]:
    """Pull request paths out of JavaScript source."""

    methods: dict[str, str] = {}

    for method, target in METHOD_CALL.findall(source):
        methods.setdefault(target, method.upper())

    candidates: list[str] = []

    for match in FETCH_CALL.findall(source) + PATH_LITERAL.findall(source):
        if _is_endpoint(match) and match not in candidates:
            candidates.append(match)

    return [
        {
            "path": path,
            "method": methods.get(path, ""),
        }
        for path in candidates[:MAX_ENDPOINTS_PER_SCRIPT]
    ]


def find_secrets(source: str) -> list[dict[str, str]]:
    secrets: list[dict[str, str]] = []

    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(source)

        if not match or is_placeholder(match.group(0)):
            continue

        secrets.append(
            {
                "kind": label,
                "match": redact(match.group(0)),
            }
        )

    return secrets


def _fetch_script(url: str, session: requests.Session) -> tuple[int | None, str]:
    try:
        response = session.get(
            url,
            timeout=PROBE_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

    except requests.RequestException:
        return None, ""

    try:
        body = response.raw.read(MAX_SCRIPT_BYTES, decode_content=True) or b""

    except (requests.RequestException, OSError):
        return response.status_code, ""

    finally:
        response.close()

    return response.status_code, body.decode("utf-8", errors="replace")


def analyze_scripts(
    script_urls: list[str],
    base_url: str,
) -> dict[str, Any]:
    """
    Fetch same-origin scripts and mine them for endpoints and secrets.

    Third-party scripts are skipped: they are outside the authorization
    the scan was given, and findings against a CDN copy of a library are
    not actionable by the application owner.
    """

    session = build_session()

    analyzed: list[dict[str, Any]] = []
    endpoints: list[dict[str, str]] = []
    seen_paths: set[str] = set()

    for url in script_urls:
        if len(analyzed) >= MAX_SCRIPTS:
            break

        if not is_same_origin(base_url, url):
            continue

        status, source = _fetch_script(url, session)

        if status != 200 or not source:
            continue

        script_endpoints = extract_endpoints(source)
        secrets = find_secrets(source)
        source_maps = SOURCE_MAP.findall(source)

        analyzed.append(
            {
                "url": url,
                "bytes": len(source),
                "endpoint_count": len(script_endpoints),
                "secrets": secrets,
                "source_maps": source_maps[:3],
            }
        )

        for endpoint in script_endpoints:
            if endpoint["path"] in seen_paths:
                continue

            seen_paths.add(endpoint["path"])

            origin = urlparse(base_url)

            endpoints.append(
                {
                    **endpoint,
                    "url": urljoin(
                        f"{origin.scheme}://{origin.netloc}",
                        endpoint["path"],
                    ),
                    "source": url,
                    "discovered_by": "javascript",
                }
            )

    return {
        "scripts": analyzed,
        "endpoints": endpoints,
    }
