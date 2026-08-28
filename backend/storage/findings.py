from __future__ import annotations

from typing import Any

from backend.storage.scans import (
    application_directory,
    load_json,
    save_json,
)


def save_findings(
    application_id: str,
    findings: list[dict[str, Any]],
) -> None:

    path = (
        application_directory(
            application_id
        )
        / "findings.json"
    )

    save_json(
        path,
        {
            "application_id":
                application_id,

            "findings":
                findings,
        },
    )


def load_findings(
    application_id: str,
) -> list[dict[str, Any]]:

    path = (
        application_directory(
            application_id
        )
        / "findings.json"
    )

    if not path.exists():
        return []

    data = load_json(
        path
    )

    return data.get(
        "findings",
        [],
    )