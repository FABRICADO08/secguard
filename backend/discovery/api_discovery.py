from __future__ import annotations

from typing import Any

from backend.discovery.http import absolute_url, build_session, probe

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


# Paths that document or expose the API surface rather than serve it.
DOCUMENTATION_PATHS = {
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/openapi.json",
    "/swagger.json",
}


def _classify(result: dict[str, Any]) -> str:
    status = result.get("status_code")

    if status is None:
        return "unreachable"

    if 200 <= status < 300:
        return "accessible"

    if status in (401, 403):
        return "protected"

    if status in (404, 410):
        return "absent"

    if 300 <= status < 400:
        return "redirected"

    return "unknown"


def discover_common_api_paths(
    base_url: str,
    probe_paths: bool = True,
) -> list[dict[str, Any]]:
    """
    Look for well-known API entry points.

    When `probe_paths` is true each candidate is requested so callers can
    distinguish paths that actually exist from ones that merely might.
    """

    session = build_session() if probe_paths else None

    results: list[dict[str, Any]] = []

    for path in COMMON_API_PATHS:
        url = absolute_url(base_url, path)

        record: dict[str, Any] = {
            "url": url,
            "path": path,
            "type": "potential-api",
            "discovered_by": "common-api-path",
            "documentation": path in DOCUMENTATION_PATHS,
            "probed": False,
            "state": "not-probed",
            "status_code": None,
            "content_type": "",
            "content_length": 0,
        }

        if session is not None:
            result = probe(url, session)

            record.update(
                {
                    "probed": True,
                    "state": _classify(result),
                    "status_code": result["status_code"],
                    "content_type": result["content_type"],
                    "content_length": result["content_length"],
                    "final_url": result["final_url"],
                    "body_preview": result["body_preview"],
                }
            )

            if record["state"] == "accessible":
                record["type"] = "api"

        results.append(record)

    return results
