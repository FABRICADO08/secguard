"""Mendix projects kept in the repository: find each .mpr and analyse its dump-mpr export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.platforms.mendix.service import analyze_model

SKIPPED_DIRECTORIES = {".git", "node_modules", "deployment", "releases", ".mendix-cache"}
EXPORT_SUFFIX = ".json"


def find_projects(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.mpr")
        if path.is_file() and not SKIPPED_DIRECTORIES.intersection(path.relative_to(root).parts)
    )


def _export_for(model: Path, project: str, projects: list[str]) -> tuple[Path | None, str]:
    """A directory holds `<project path>.json` per project; a single file serves a single project."""

    if model.is_dir():
        candidate = model / f"{project}{EXPORT_SUFFIX}"
        return (candidate, "") if candidate.is_file() else (None, "No dump-mpr export was produced for this project.")

    if len(projects) == 1:
        return model, ""

    return None, "One export was supplied for several projects; pass a directory of <project>.mpr.json exports."


def _repository_finding(finding: dict[str, Any], project: str) -> dict[str, Any]:
    element = str(finding.get("location") or "")
    title = str(finding.get("title") or "")
    return {
        **finding,
        "title": f"{title}: {element}" if element else title,
        "location": project,
        "evidence": {**(finding.get("evidence") or {}), "element": element},
    }


def _analyse_project(project: str, export: Path | None, reason: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    entry: dict[str, Any] = {"path": project, "analyzed": False}

    if export is None:
        entry["reason"] = reason
        return entry, []

    try:
        result = analyze_model(json.loads(export.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        entry["reason"] = f"Could not analyse the Mendix export: {exc}"
        return entry, []

    findings = [_repository_finding(finding, project) for finding in result["findings"]]
    entry.update(
        analyzed=True,
        modules=len(result["model"]["modules"]),
        entities=len(result["model"]["entities"]),
        findings=len(findings),
    )
    return entry, findings


def analyse_mendix(root: Path, model: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Per-project Mendix summary for the report plus findings located at each project file."""

    projects = find_projects(root)

    if not projects and model is not None and model.is_file():
        projects = [model.name]

    if not projects:
        return {}, []

    entries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for project in projects:
        if model is None:
            export, reason = None, "No dump-mpr export was supplied, so the model was not analysed."
        else:
            export, reason = _export_for(model, project, projects)
        entry, project_findings = _analyse_project(project, export, reason)
        entries.append(entry)
        findings.extend(project_findings)

    summary = {
        "analyzed": all(entry["analyzed"] for entry in entries),
        "projects": entries,
        "findings": len(findings),
    }
    return summary, findings


__all__ = ["analyse_mendix", "find_projects"]
