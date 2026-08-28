from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

APPLICATIONS_DIR = (
    ROOT / "data" / "applications"
)


def ensure_storage() -> None:

    APPLICATIONS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def application_directory(
    application_id: str,
) -> Path:

    ensure_storage()

    directory = (
        APPLICATIONS_DIR
        / application_id
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def save_json(
    path: Path,
    data: dict[str, Any],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    temporary_path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    temporary_path.replace(
        path
    )


def load_json(
    path: Path,
) -> dict[str, Any]:

    if not path.exists():

        raise FileNotFoundError(
            f"Stored file does not exist: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def save_application(
    application: dict[str, Any],
) -> Path:

    application_id = application["id"]

    directory = application_directory(
        application_id
    )

    path = (
        directory
        / "application.json"
    )

    save_json(
        path,
        application,
    )

    return path


def load_application(
    application_id: str,
) -> dict[str, Any]:

    path = (
        application_directory(
            application_id
        )
        / "application.json"
    )

    return load_json(
        path
    )


def application_exists(
    application_id: str,
) -> bool:

    path = (
        APPLICATIONS_DIR
        / application_id
        / "application.json"
    )

    return path.exists()


def list_applications() -> list[dict[str, Any]]:

    ensure_storage()

    applications = []

    for directory in APPLICATIONS_DIR.iterdir():

        if not directory.is_dir():
            continue

        application_file = (
            directory
            / "application.json"
        )

        if not application_file.exists():
            continue

        try:

            data = load_json(
                application_file
            )

            security = data.get(
                "security",
                {},
            ) or {}

            applications.append(
                {
                    "id":
                        data.get(
                            "id"
                        ),

                    "name":
                        data.get(
                            "name"
                        ),

                    "url":
                        data.get(
                            "final_url"
                        ),

                    "platform":
                        data.get(
                            "platform",
                            "Unknown",
                        ),

                    "status":
                        data.get(
                            "status",
                            "unknown",
                        ),

                    "created_at":
                        data.get(
                            "created_at"
                        ),

                    "updated_at":
                        data.get(
                            "updated_at"
                        ),

                    "risk_score":
                        security.get(
                            "risk_score",
                            0,
                        ),

                    "risk_grade":
                        security.get(
                            "risk_grade",
                            "",
                        ),

                    "total_findings":
                        security.get(
                            "total_findings",
                            len(
                                security.get(
                                    "findings",
                                    [],
                                )
                            ),
                        ),

                    "severity_counts":
                        security.get(
                            "severity_counts",
                            {},
                        ),
                }
            )

        except (
            json.JSONDecodeError,
            OSError,
            KeyError,
        ):

            continue

    applications.sort(
        key=lambda item:
            item.get(
                "updated_at",
                "",
            ),
        reverse=True,
    )

    return applications