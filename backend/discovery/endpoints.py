from __future__ import annotations

from urllib.parse import urlparse


API_MARKERS = (
    "/api/",
    "/api",
    "/rest/",
    "/rest",
    "/graphql",
    "/odata",
    "/swagger",
    "/openapi",
    "/v1/",
    "/v2/",
    "/v3/",
)


def _add_endpoint(
    endpoints: list[dict],
    seen: set[tuple[str, str]],
    url: str,
    endpoint_type: str,
    method: str = "GET",
) -> None:
    method = method.upper()
    key = (method, url)

    if key in seen:
        return

    seen.add(key)
    parsed = urlparse(url)
    endpoints.append(
        {
            "url": url,
            "path": parsed.path,
            "method": method,
            "type": endpoint_type,
        }
    )


def _add_link_endpoint(
    endpoints: list[dict],
    seen: set[tuple[str, str]],
    url: str,
) -> None:
    path = urlparse(url).path.lower()
    endpoint_type = (
        "api"
        if any(marker in path for marker in API_MARKERS)
        else "page"
    )
    _add_endpoint(endpoints, seen, url, endpoint_type)


def discover_endpoints(
    links: list[str],
    forms: list[dict],
) -> list[dict]:
    endpoints = []
    seen = set()

    for url in links:
        _add_link_endpoint(endpoints, seen, url)

    for form in forms:
        _add_endpoint(
            endpoints,
            seen,
            form.get(
                "action",
                "",
            ),
            "form",
            form.get(
                "method",
                "GET",
            ),
        )

    return endpoints