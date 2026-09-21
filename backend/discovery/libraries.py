"""
Identify the components a page ships, together with their versions.

Only evidence the target itself publishes is used: script filenames,
version banners printed by the libraries, and server headers. Nothing is
downloaded or executed beyond what the crawl already fetched.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

VERSION = r"(\d+(?:\.\d+){1,3})"


def _filename_pattern(token: str) -> re.Pattern[str]:
    """
    A versioned filename for `token` and nothing else.

    Anchored at the start of the filename and followed immediately by
    the version, so neither a package that merely ends in the token
    (`notjquery-1.12.4.js`) nor one that merely starts with it
    (`react-bootstrap-1.6.0.js`) is mistaken for the library itself.
    """

    return re.compile(rf"\A{token}[.\-]v?{VERSION}", re.IGNORECASE)


# Script URLs of the form .../jquery-3.4.1.min.js or /jquery/3.4.1/...
FILENAME_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jQuery UI", _filename_pattern(r"jquery[.\-]ui")),
    ("jQuery", _filename_pattern("jquery")),
    ("Bootstrap", _filename_pattern("bootstrap")),
    ("AngularJS", _filename_pattern("angular")),
    ("Lodash", _filename_pattern("lodash")),
    ("Underscore", _filename_pattern("underscore")),
    ("Moment", _filename_pattern("moment")),
    ("Handlebars", _filename_pattern("handlebars")),
    ("Axios", _filename_pattern("axios")),
    ("DOMPurify", _filename_pattern("purify")),
    ("CKEditor", _filename_pattern("ckeditor")),
    ("React", _filename_pattern("react")),
    ("Vue", _filename_pattern("vue")),
)

# CDN layouts put the version in a path segment: /ajax/libs/jquery/3.4.1/
PATH_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jQuery UI", re.compile(rf"/jquery-?ui/{VERSION}/", re.IGNORECASE)),
    ("jQuery", re.compile(rf"/jquery/{VERSION}/", re.IGNORECASE)),
    ("Bootstrap", re.compile(rf"/bootstrap/{VERSION}/", re.IGNORECASE)),
    ("AngularJS", re.compile(rf"/angular(?:js)?/{VERSION}/", re.IGNORECASE)),
    ("Lodash", re.compile(rf"/lodash[.\w-]*/{VERSION}/", re.IGNORECASE)),
    ("Underscore", re.compile(rf"/underscore[.\w-]*/{VERSION}/", re.IGNORECASE)),
    ("Moment", re.compile(rf"/moment[.\w-]*/{VERSION}/", re.IGNORECASE)),
    ("Handlebars", re.compile(rf"/handlebars[.\w-]*/{VERSION}/", re.IGNORECASE)),
    ("Axios", re.compile(rf"/axios/{VERSION}/", re.IGNORECASE)),
    ("DOMPurify", re.compile(rf"/dompurify/{VERSION}/", re.IGNORECASE)),
    ("CKEditor", re.compile(rf"/ckeditor/{VERSION}/", re.IGNORECASE)),
)

# Banners the libraries themselves print into the markup or the bundle.
BODY_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jQuery", re.compile(rf"jQuery\s+(?:JavaScript Library\s+)?v{VERSION}")),
    ("Bootstrap", re.compile(rf"Bootstrap\s+v{VERSION}")),
    ("AngularJS", re.compile(rf"AngularJS\s+v{VERSION}")),
    ("Angular", re.compile(rf"ng-version=[\"']{VERSION}[\"']")),
    ("Moment", re.compile(rf"moment\.version\s*=\s*[\"']{VERSION}[\"']")),
    ("Lodash", re.compile(rf"lodash\s+{VERSION}\s+", re.IGNORECASE)),
    ("Underscore", re.compile(rf"Underscore\.js\s+{VERSION}", re.IGNORECASE)),
    ("Handlebars", re.compile(rf"Handlebars\s+v{VERSION}", re.IGNORECASE)),
    ("DOMPurify", re.compile(rf"DOMPurify\s+{VERSION}", re.IGNORECASE)),
    ("CKEditor", re.compile(rf"CKEditor\s+{VERSION}", re.IGNORECASE)),
)

# Server-side components disclosed in response headers.
SERVER_COMPONENTS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("nginx", "server", re.compile(rf"nginx/{VERSION}", re.IGNORECASE)),
    ("Apache", "server", re.compile(rf"apache(?:/| )?{VERSION}", re.IGNORECASE)),
    ("PHP", "server", re.compile(rf"php/{VERSION}", re.IGNORECASE)),
    ("PHP", "x-powered-by", re.compile(rf"php/{VERSION}", re.IGNORECASE)),
    ("ASP.NET", "x-aspnet-version", re.compile(rf"^{VERSION}", re.IGNORECASE)),
    ("Express", "x-powered-by", re.compile(rf"express/{VERSION}", re.IGNORECASE)),
    ("OpenSSL", "server", re.compile(rf"openssl/{VERSION}", re.IGNORECASE)),
)


def _record(
    name: str,
    version: str,
    source: str,
    evidence: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "source": source,
        "evidence": evidence,
    }


def _split_angular(name: str, version: str) -> str:
    """
    AngularJS never left 1.x; anything above it is the other framework.

    They share the `angular` filename token but not a version line, so
    calling Angular 17 "AngularJS" would hand it AngularJS advisories.
    """

    if name != "AngularJS" or version.startswith("1."):
        return name

    return "Angular"


def _from_url(url: str) -> tuple[str, str, str] | None:
    parsed = urlparse(url)
    path = unquote(parsed.path)

    for name, pattern in PATH_LIBRARIES:
        match = pattern.search(path)

        if match:
            return (
                _split_angular(name, match.group(1)),
                match.group(1),
                "script-path",
            )

    filename = path.rsplit("/", 1)[-1]

    for name, pattern in FILENAME_LIBRARIES:
        match = pattern.search(filename)

        if match:
            return (
                _split_angular(name, match.group(1)),
                match.group(1),
                "script-filename",
            )

    return None


def detect_in_source(url: str, source: str) -> list[dict[str, Any]]:
    """
    Version banners a served script prints about itself.

    A bundled or renamed copy carries no version in its filename, so the
    banner is the only version the target discloses for it.
    """

    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for name, pattern in BODY_LIBRARIES:
        match = pattern.search(source)

        if match is None or (name, match.group(1)) in seen:
            continue

        seen.add((name, match.group(1)))

        found.append(
            _record(name, match.group(1), "script-banner", url)
        )

    return found


def detect_libraries(
    scripts: list[str],
    body: str,
    headers: dict[str, str],
    extra: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Collect (component, version) pairs the target discloses.

    The first sighting of a component wins: a page that loads the same
    library twice should produce one entry, not two findings. `extra`
    carries sightings made elsewhere — banners inside fetched scripts —
    through the same de-duplication.
    """

    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str, source: str, evidence: str) -> None:
        key = (name.lower(), version)

        if not name or not version or key in seen:
            return

        seen.add(key)

        found.append(_record(name, version, source, evidence))

    for url in scripts:
        detected = _from_url(str(url))

        if detected:
            name, version, source = detected

            add(name, version, source, str(url))

    for name, pattern in BODY_LIBRARIES:
        match = pattern.search(body)

        if match:
            add(name, match.group(1), "page-body", match.group(0))

    lowered = {str(key).lower(): str(value) for key, value in headers.items()}

    for name, header, pattern in SERVER_COMPONENTS:
        match = pattern.search(lowered.get(header, ""))

        if match:
            add(name, match.group(1), f"header:{header}", match.group(0))

    for entry in extra or ():
        add(
            str(entry.get("name", "")),
            str(entry.get("version", "")),
            str(entry.get("source", "script-banner")),
            str(entry.get("evidence", "")),
        )

    return found
