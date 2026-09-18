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

# Script URLs of the form .../jquery-3.4.1.min.js or /jquery/3.4.1/...
FILENAME_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jQuery UI", re.compile(rf"jquery[.\-]ui[.\-]{VERSION}", re.IGNORECASE)),
    ("jQuery", re.compile(rf"jquery[.\-]{VERSION}", re.IGNORECASE)),
    ("Bootstrap", re.compile(rf"bootstrap[.\-]{VERSION}", re.IGNORECASE)),
    ("AngularJS", re.compile(rf"angular[.\-]{VERSION}", re.IGNORECASE)),
    ("Lodash", re.compile(rf"lodash[.\-]{VERSION}", re.IGNORECASE)),
    ("Underscore", re.compile(rf"underscore[.\-]{VERSION}", re.IGNORECASE)),
    ("Moment", re.compile(rf"moment[.\-]{VERSION}", re.IGNORECASE)),
    ("Handlebars", re.compile(rf"handlebars[.\-]{VERSION}", re.IGNORECASE)),
    ("Axios", re.compile(rf"axios[.\-]{VERSION}", re.IGNORECASE)),
    ("DOMPurify", re.compile(rf"purify[.\-]{VERSION}", re.IGNORECASE)),
    ("CKEditor", re.compile(rf"ckeditor[.\-]{VERSION}", re.IGNORECASE)),
    ("React", re.compile(rf"react[.\-]{VERSION}", re.IGNORECASE)),
    ("Vue", re.compile(rf"vue[.\-]{VERSION}", re.IGNORECASE)),
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


def _from_url(url: str) -> tuple[str, str, str] | None:
    parsed = urlparse(url)
    path = unquote(parsed.path)

    for name, pattern in PATH_LIBRARIES:
        match = pattern.search(path)

        if match:
            return name, match.group(1), "script-path"

    filename = path.rsplit("/", 1)[-1]

    for name, pattern in FILENAME_LIBRARIES:
        match = pattern.search(filename)

        if match:
            return name, match.group(1), "script-filename"

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
