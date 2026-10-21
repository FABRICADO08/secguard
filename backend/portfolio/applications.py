"""The latest scan and display name of each GitHub-connected application."""

from __future__ import annotations

from backend.security import github_auth
from backend.storage import application_names
from backend.storage.scans import list_applications


def latest_repository_scans() -> dict[str, dict]:
    """Return the most recently updated repository scan per repository."""
    latest: dict[str, dict] = {}
    for application in list_applications():
        if application.get("platform") != "Repository":
            continue
        key = github_auth.repository_name(application).lower()
        if key and str(application.get("updated_at") or "") >= str(
            (latest.get(key) or {}).get("updated_at") or ""
        ):
            latest[key] = application
    return latest


def application_name(repository: str, application: dict | None) -> str:
    """Resolve the display name configured for a repository application."""
    stored = str((application or {}).get("name") or "")
    if stored.lower() == repository.lower():
        stored = ""
    return (
        application_names.name_for(repository)
        or stored
        or repository.rsplit("/", 1)[-1]
    )
