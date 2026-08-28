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


def discover_endpoints(
    links: list[str],
    forms: list[dict],
) -> list[dict]:

    endpoints = []

    seen = set()

    def add(
        url: str,
        endpoint_type: str,
        method: str = "GET",
    ) -> None:

        key = (
            method.upper(),
            url,
        )

        if key in seen:
            return

        seen.add(key)

        parsed = urlparse(url)

        endpoints.append(
            {
                "url": url,
                "path": parsed.path,
                "method": method.upper(),
                "type": endpoint_type,
            }
        )

    for url in links:

        path = urlparse(
            url
        ).path.lower()

        if any(
            marker in path
            for marker in API_MARKERS
        ):

            add(
                url,
                "api",
            )

        else:

            add(
                url,
                "page",
            )

    for form in forms:

        add(
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