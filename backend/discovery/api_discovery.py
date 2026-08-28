from __future__ import annotations

from urllib.parse import urljoin


COMMON_API_PATHS = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/rest",
    "/rest/",
    "/graphql",
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/openapi.json",
    "/swagger.json",
    "/odata",
]


def discover_common_api_paths(
    base_url: str,
) -> list[dict]:

    results = []

    for path in COMMON_API_PATHS:

        results.append(
            {
                "url":
                    urljoin(
                        base_url.rstrip("/") + "/",
                        path.lstrip("/"),
                    ),

                "path":
                    path,

                "type":
                    "potential-api",

                "discovered_by":
                    "common-api-path",
            }
        )

    return results