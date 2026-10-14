"""Mendix projects kept in the repository: find the .mpr and analyse its dump-mpr export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.platforms.mendix.service import analyze_model

SKIPPED_DIRECTORIES = {".git", "node_modules", "deployment", "releases", ".mendix-cache"}


def find_projects(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.mpr")
        if path.is_file() and not SKIPPED_DIRECTORIES.intersection(path.relative_to(root).parts)
    )


def _repository_finding(finding: dict[str, Any], project: str) -> dict[str, Any]:
    element = str(finding.get("location") or "")
    title = str(finding.get("title") or "")
    return {
        **finding,
        "title": f"{title}: {element}" if element else title,
        "location": project,
        "evidence": {**(finding.get("evidence") or {}), "element": element},
    }


def analyse_mendix(root: Path, model_path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Mendix summary for the report plus findings located at the project file."""

    projects = find_projects(root)

    if not projects and model_path is None:
        return {}, []

    summary: dict[str, Any] = {"projects": projects, "analyzed": False}

    if model_path is None:
        summary["reason"] = "No dump-mpr export was supplied, so the model was not analysed."
        return summary, []

    try:
        result = analyze_model(json.loads(model_path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        summary["reason"] = f"Could not analyse the Mendix export: {exc}"
        return summary, []

    project = projects[0] if projects else model_path.name
    findings = [_repository_finding(finding, project) for finding in result["findings"]]
    model = result["model"]

    summary.update(
        analyzed=True,
        modules=len(model["modules"]),
        entities=len(model["entities"]),
        findings=len(findings),
    )
    return summary, findings


__all__ = ["analyse_mendix", "find_projects"]
