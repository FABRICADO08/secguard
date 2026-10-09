from __future__ import annotations

import re


def _add(
    technologies: list[dict],
    name: str,
    category: str,
    confidence: str,
    evidence: str,
) -> None:
    if any(item["name"] == name for item in technologies):
        return

    technologies.append(
        {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence,
        }
    )


def _detect_platforms(body_lower: str, technologies: list[dict]) -> None:
    platform_markers = {
        "Mendix": (
            r"mendix",
            r"mxruntime",
            r"mxui",
            r"mendix-client",
            r"mx-object",
        ),
        "OutSystems": (
            r"outsystems",
            r"outsystemsui",
            r"/scripts/outsystems",
            r"moduleservices/moduleversioninfo",
            r"osjstooltip",
            r"nr2users",
            r"osvisit",
        ),
    }

    for name, patterns in platform_markers.items():
        for pattern in patterns:
            if re.search(pattern, body_lower):
                _add(
                    technologies,
                    name,
                    "Platform",
                    "high",
                    f"Page content matched: {pattern}",
                )
                break


def _detect_frontends(body_lower: str, technologies: list[dict]) -> None:
    frontend_markers = (
        (
            "React",
            ("react", "__next_data__", "data-reactroot"),
            "medium",
            "React-related page markers detected.",
        ),
        (
            "Angular",
            ("ng-version", "angular"),
            "medium",
            "Angular-related page markers detected.",
        ),
        (
            "Vue",
            ("vue", "data-v-"),
            "low",
            "Vue-related page markers detected.",
        ),
    )

    for name, markers, confidence, evidence in frontend_markers:
        if any(marker in body_lower for marker in markers):
            _add(technologies, name, "Frontend", confidence, evidence)


def _detect_backends(
    body_lower: str,
    headers: dict[str, str],
    technologies: list[dict],
) -> None:
    if (
        re.search(r"asp\.?net", body_lower)
        or "x-aspnetmvc-version" in headers
    ):
        _add(
            technologies,
            "ASP.NET",
            "Backend",
            "medium",
            "ASP.NET-related markers detected.",
        )

    if (
        "php" in headers.get("x-powered-by", "")
        or ".php" in body_lower
    ):
        _add(
            technologies,
            "PHP",
            "Backend",
            "low",
            "PHP-related response markers detected.",
        )

    if any(marker in body_lower for marker in ("spring", "jsessionid")):
        _add(
            technologies,
            "Java",
            "Backend",
            "low",
            "Java/Spring-related markers detected.",
        )

    if (
        "node.js" in headers.get("x-powered-by", "")
        or "express" in body_lower
    ):
        _add(
            technologies,
            "Node.js",
            "Backend",
            "medium",
            "Node.js/Express-related markers detected.",
        )


def detect_technologies(response: dict) -> list[dict]:
    technologies: list[dict] = []
    headers = {
        key.lower(): str(value).lower()
        for key, value in response.get("headers", {}).items()
    }
    body_lower = str(response.get("body", "")).lower()

    _detect_platforms(body_lower, technologies)
    _detect_frontends(body_lower, technologies)
    _detect_backends(body_lower, headers, technologies)

    server = headers.get("server", "")
    if server:
        _add(
            technologies,
            server,
            "Server",
            "medium",
            f"HTTP Server header: {server}",
        )

    return technologies
