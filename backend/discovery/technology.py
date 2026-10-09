from __future__ import annotations

import re


PLATFORM_MARKERS = {
    "Mendix": (r"mendix", r"mxruntime", r"mxui", r"mendix-client", r"mx-object"),
    "OutSystems": (
        r"outsystems", r"outsystemsui", r"/scripts/outsystems",
        r"moduleservices/moduleversioninfo", r"osjstooltip", r"nr2users", r"osvisit",
    ),
}


def _matches_any(patterns: tuple[str, ...], body: str) -> str:
    return next((pattern for pattern in patterns if re.search(pattern, body)), "")


def detect_technologies(
    response: dict,
) -> list[dict]:

    technologies = []

    headers = {
        key.lower(): str(value).lower()
        for key, value in response.get(
            "headers",
            {},
        ).items()
    }

    body = str(
        response.get(
            "body",
            "",
        )
    )

    body_lower = body.lower()

    def add(
        name: str,
        category: str,
        confidence: str,
        evidence: str,
    ) -> None:

        if any(
            item["name"] == name
            for item in technologies
        ):
            return

        technologies.append(
            {
                "name": name,
                "category": category,
                "confidence": confidence,
                "evidence": evidence,
            }
        )

    for name, patterns in PLATFORM_MARKERS.items():
        match = _matches_any(patterns, body_lower)
        if match:
            add(name, "Platform", "high", f"Page content matched: {match}")

    marker_rules = (
        ("React", ("react", "__next_data__", "data-reactroot"), "Frontend", "medium", "React-related page markers detected."),
        ("Angular", ("ng-version", "angular"), "Frontend", "medium", "Angular-related page markers detected."),
        ("Vue", ("vue", "data-v-"), "Frontend", "low", "Vue-related page markers detected."),
        ("Java", ("spring", "jsessionid"), "Backend", "low", "Java/Spring-related markers detected."),
    )
    for name, markers, category, confidence, evidence in marker_rules:
        if any(marker in body_lower for marker in markers):
            add(name, category, confidence, evidence)

    response_rules = (
        (
            "ASP.NET", "Backend", "medium", "ASP.NET-related markers detected.",
            bool(re.search(r"asp\.?net", body_lower)) or "x-aspnetmvc-version" in headers,
        ),
        (
            "PHP", "Backend", "low", "PHP-related response markers detected.",
            "php" in headers.get("x-powered-by", "") or ".php" in body_lower,
        ),
        (
            "Node.js", "Backend", "medium", "Node.js/Express-related markers detected.",
            "node.js" in headers.get("x-powered-by", "") or "express" in body_lower,
        ),
    )
    for name, category, confidence, evidence, matched in response_rules:
        if matched:
            add(name, category, confidence, evidence)

    # --------------------------------------------------------
    # Server header
    # --------------------------------------------------------

    server = headers.get(
        "server",
        "",
    )

    if server:

        add(
            server,
            "Server",
            "medium",
            f"HTTP Server header: {server}",
        )

    return technologies