from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from backend.storage import db

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
) -> None:

    if db.use_database():
        db.save_application(application)

        return

    application_id = application["id"]

    directory = application_directory(
        application_id
    )

    save_json(
        directory / "application.json",
        application,
    )


def load_application(
    application_id: str,
) -> dict[str, Any]:

    if db.use_database():
        return db.load_application(application_id)

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

    if db.use_database():
        return db.application_exists(application_id)

    path = (
        APPLICATIONS_DIR
        / application_id
        / "application.json"
    )

    return path.exists()


def delete_application(
    application_id: str,
) -> bool:
    """
    Remove an application and everything stored under it.

    Returns False when the application does not exist or the id does
    not resolve to a direct child of the applications directory.
    """

    if db.use_database():
        return db.delete_application(application_id)

    ensure_storage()

    directory = (
        APPLICATIONS_DIR
        / application_id
    ).resolve()

    if directory.parent != APPLICATIONS_DIR.resolve():
        return False

    if not directory.is_dir():
        return False

    shutil.rmtree(
        directory
    )

    return True


def _application_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Build the public portfolio summary for one stored application."""
    return db.application_summary(data)


def _read_application_summary(directory: Path) -> dict[str, Any] | None:
    application_file = directory / "application.json"

    if not application_file.exists():
        return None

    try:
        return _application_summary(load_json(application_file))
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def list_applications() -> list[dict[str, Any]]:
    """List stored application summaries in most-recently-updated order."""
    if db.use_database():
        return db.list_applications()

    ensure_storage()
    applications = [
        summary
        for directory in APPLICATIONS_DIR.iterdir()
        if directory.is_dir()
        if (summary := _read_application_summary(directory)) is not None
    ]
    applications.sort(
        key=lambda item: item.get("updated_at", ""),
        reverse=True,
    )
    return applications