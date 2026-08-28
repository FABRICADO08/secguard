from __future__ import annotations

import re


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

    # --------------------------------------------------------
    # Mendix
    # --------------------------------------------------------

    mendix_patterns = [
        r"mendix",
        r"mxruntime",
        r"mxui",
        r"mendix-client",
        r"mx-object",
    ]

    for pattern in mendix_patterns:

        if re.search(
            pattern,
            body_lower,
        ):

            add(
                "Mendix",
                "Platform",
                "high",
                f"Page content matched: {pattern}",
            )

            break

    # --------------------------------------------------------
    # React
    # --------------------------------------------------------

    if (
        "react" in body_lower
        or "__next_data__" in body_lower
        or "data-reactroot" in body_lower
    ):

        add(
            "React",
            "Frontend",
            "medium",
            "React-related page markers detected.",
        )

    # --------------------------------------------------------
    # Angular
    # --------------------------------------------------------

    if (
        "ng-version" in body_lower
        or "angular" in body_lower
    ):

        add(
            "Angular",
            "Frontend",
            "medium",
            "Angular-related page markers detected.",
        )

    # --------------------------------------------------------
    # Vue
    # --------------------------------------------------------

    if (
        "vue" in body_lower
        or "data-v-" in body_lower
    ):

        add(
            "Vue",
            "Frontend",
            "low",
            "Vue-related page markers detected.",
        )

    # --------------------------------------------------------
    # ASP.NET
    # --------------------------------------------------------

    if (
        "asp.net" in body_lower
        or "aspnet" in body_lower
        or "x-aspnetmvc-version" in headers
    ):

        add(
            "ASP.NET",
            "Backend",
            "medium",
            "ASP.NET-related markers detected.",
        )

    # --------------------------------------------------------
    # PHP
    # --------------------------------------------------------

    if (
        "php" in headers.get(
            "x-powered-by",
            "",
        )
        or ".php" in body_lower
    ):

        add(
            "PHP",
            "Backend",
            "low",
            "PHP-related response markers detected.",
        )

    # --------------------------------------------------------
    # Java
    # --------------------------------------------------------

    if any(
        marker in body_lower
        for marker in [
            "spring",
            "jsessionid",
        ]
    ):

        add(
            "Java",
            "Backend",
            "low",
            "Java/Spring-related markers detected.",
        )

    # --------------------------------------------------------
    # Node.js
    # --------------------------------------------------------

    if (
        "node.js" in headers.get(
            "x-powered-by",
            "",
        )
        or "express" in body_lower
    ):

        add(
            "Node.js",
            "Backend",
            "medium",
            "Node.js/Express-related markers detected.",
        )

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