"""
Portfolio open-source health: every third-party library across the
latest scan of each GitHub-connected system.

The answer to "which applications ship this library, and at which
version?" needs one inventory over all systems, so dependencies are
folded by ecosystem and package name. Each library keeps the systems
using it, the advisories found against those versions, how far the
oldest usage is behind the latest release and the most restrictive
licence any usage declares.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.portfolio.summary import lineage_key
from backend.repository.licenses import (
    NETWORK_COPYLEFT,
    NON_COMMERCIAL,
    RESTRICTIVENESS,
    STRONG_COPYLEFT,
    UNKNOWN,
)
from backend.risk.severity import (
    SEVERITY_ORDER,
    empty_severity_counts,
    normalize_severity,
)

LICENCE_RISK = frozenset({STRONG_COPYLEFT, NETWORK_COPYLEFT, NON_COMMERCIAL})

REPOSITORY_PLATFORM = "Repository"


def _moment(application: dict[str, Any]) -> str:
    return str(application.get("updated_at") or application.get("created_at") or "")


def latest_repository_systems(applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The newest scan of every GitHub-connected system."""
    latest: dict[str, dict[str, Any]] = {}
    for application in applications:
        if application.get("platform") != REPOSITORY_PLATFORM:
            continue
        key = lineage_key(application)
        if key not in latest or _moment(application) >= _moment(latest[key]):
            latest[key] = application
    return sorted(latest.values(), key=lambda item: str(item.get("name") or "").lower())


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _behind(dependency: dict[str, Any]) -> dict[str, int]:
    freshness = dependency.get("freshness")
    behind = freshness.get("behind") if isinstance(freshness, dict) else None
    behind = behind if isinstance(behind, dict) else {}
    return {part: _count(behind.get(part)) for part in ("major", "minor", "patch")}


def _advisories(dependency: dict[str, Any]) -> list[dict[str, Any]]:
    raw = dependency.get("vulnerabilities")
    advisories = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not _text(item.get("id")):
            continue
        advisories.append(
            {
                "id": item["id"],
                "severity": normalize_severity(item.get("severity")),
                "summary": _text(item.get("summary"))[:300],
                "minimum_fix": _text(item.get("minimum_fix")),
            }
        )
    return advisories


def _usage(system: dict[str, Any], dependency: dict[str, Any]) -> dict[str, Any]:
    return {
        "system_id": system["id"],
        "system": system["name"],
        "version": _text(dependency.get("version")) or _text(dependency.get("spec")),
        "direct": dependency.get("direct") is True,
        "scope": _text(dependency.get("scope")),
        "reachability": _text(dependency.get("reachability")) or "unknown",
        "behind": _behind(dependency),
        "advisories": [advisory["id"] for advisory in _advisories(dependency)],
    }


def _worst(severities: list[str]) -> str:
    return max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, 0), default="")


def _most_restrictive(categories: list[str]) -> str:
    known = [category for category in categories if category in RESTRICTIVENESS]
    return max(known, key=RESTRICTIVENESS.__getitem__, default=UNKNOWN)


def _library_key(dependency: dict[str, Any]) -> tuple[str, str] | None:
    name = _text(dependency.get("name")).strip()
    if not name:
        return None
    return _text(dependency.get("ecosystem")), name.lower()


def _new_library(dependency: dict[str, Any]) -> dict[str, Any]:
    return {
        "ecosystem": _text(dependency.get("ecosystem")),
        "name": _text(dependency.get("name")).strip(),
        "latest": "",
        "_licences": {},
        "_advisories": {},
        "usages": [],
    }


def _add_usage(library: dict[str, Any], system: dict[str, Any], dependency: dict[str, Any]) -> None:
    library["usages"].append(_usage(system, dependency))
    freshness = dependency.get("freshness")
    latest = _text(freshness.get("latest")) if isinstance(freshness, dict) else ""
    library["latest"] = library["latest"] or latest
    licence = _text(dependency.get("license_spdx")) or _text(dependency.get("license"))
    category = _text(dependency.get("license_category")) or UNKNOWN
    library["_licences"].setdefault(category, licence)
    for advisory in _advisories(dependency):
        library["_advisories"].setdefault(advisory["id"], advisory)


def _finish_library(library: dict[str, Any]) -> dict[str, Any]:
    licences = library.pop("_licences")
    advisories = sorted(
        library.pop("_advisories").values(),
        key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["id"]),
    )
    category = _most_restrictive(list(licences))
    usages = sorted(library["usages"], key=lambda usage: (usage["system"].lower(), usage["version"]))
    return {
        **library,
        "usages": usages,
        "systems": len({usage["system_id"] for usage in usages}),
        "versions": sorted({usage["version"] for usage in usages if usage["version"]}),
        "license": licences.get(category, ""),
        "license_category": category,
        "license_risk": category in LICENCE_RISK,
        "advisories": advisories,
        "severity": _worst([item["severity"] for item in advisories]),
        "major_behind": max((usage["behind"]["major"] for usage in usages), default=0),
    }


def _system_record(application: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    report = application.get("repository") if isinstance(application.get("repository"), dict) else {}
    freshness = report.get("freshness") if isinstance(report.get("freshness"), dict) else {}
    health = report.get("health") if isinstance(report.get("health"), dict) else {}
    aspect = health.get("open_source") if isinstance(health.get("open_source"), dict) else {}
    return {
        "id": str(summary.get("id") or ""),
        "name": str(summary.get("name") or summary.get("repository") or ""),
        "scan_date": _moment(summary),
        "rating": aspect.get("stars"),
        "libyears": freshness.get("libyears"),
        "freshness_index": freshness.get("freshness_index"),
    }


def _dependencies(application: dict[str, Any]) -> list[dict[str, Any]]:
    report = application.get("repository")
    raw = report.get("dependencies") if isinstance(report, dict) else None
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _dependency_flags(dependency: dict[str, Any]) -> tuple[str, bool, bool, bool]:
    return (
        _worst([item["severity"] for item in _advisories(dependency)]),
        dependency.get("direct") is True,
        _behind(dependency)["major"] > 0,
        _text(dependency.get("license_category")) in LICENCE_RISK,
    )


def _system_totals(system: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    flags = [_dependency_flags(dependency) for dependency in dependencies]
    severities = [flag[0] for flag in flags if flag[0]]
    return {
        **system,
        "dependencies": len(dependencies),
        "direct": sum(flag[1] for flag in flags),
        "vulnerable": len(severities),
        "severity": _worst(severities),
        "major_behind": sum(flag[2] for flag in flags),
        "license_risk": sum(flag[3] for flag in flags),
    }


def _totals(systems: list[dict[str, Any]], libraries: list[dict[str, Any]]) -> dict[str, Any]:
    advisories = empty_severity_counts()
    licences: dict[str, int] = {}
    for library in libraries:
        for advisory in library["advisories"]:
            advisories[advisory["severity"]] += 1
        licences[library["license_category"]] = licences.get(library["license_category"], 0) + 1
    return {
        "systems": len(systems),
        "libraries": len(libraries),
        "usages": sum(len(library["usages"]) for library in libraries),
        "vulnerable": sum(1 for library in libraries if library["advisories"]),
        "major_behind": sum(1 for library in libraries if library["major_behind"]),
        "license_risk": sum(1 for library in libraries if library["license_risk"]),
        "advisories": advisories,
        "license_categories": dict(sorted(licences.items())),
    }


def _library_order(library: dict[str, Any]) -> tuple:
    return (
        -SEVERITY_ORDER.get(library["severity"], -1) if library["severity"] else 1,
        -library["systems"],
        library["name"].lower(),
    )


def open_source_overview(
    applications: list[dict[str, Any]],
    load: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Fold the dependencies of every system's latest scan into one library inventory."""
    systems: list[dict[str, Any]] = []
    libraries: dict[tuple[str, str], dict[str, Any]] = {}
    for summary in latest_repository_systems(applications):
        application = load(str(summary.get("id") or ""))
        dependencies = _dependencies(application)
        system = _system_record(application, summary)
        systems.append(_system_totals(system, dependencies))
        for dependency in dependencies:
            key = _library_key(dependency)
            if key is not None:
                _add_usage(libraries.setdefault(key, _new_library(dependency)), system, dependency)
    finished = sorted((_finish_library(library) for library in libraries.values()), key=_library_order)
    return {"totals": _totals(systems, finished), "systems": systems, "libraries": finished}
