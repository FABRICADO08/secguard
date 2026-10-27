"""
Manifest edits that upgrade vulnerable direct dependencies.

Only declarations SecGuard can rewrite safely are planned: an exact pin in
a pip requirements file and an exact, caret or tilde version in
package.json. Each upgrade targets the smallest release that clears every
known advisory, preferring one within the current major version.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any

from backend.repository.dependency import normalize_package
from backend.repository.versions import NPM, PYPI

_VERSION = re.compile(r"\d+(?:\.\d+){0,3}(?:[-+.!]?[0-9A-Za-z]+)*")
_NAME = re.compile(r"(?:@[\w.-]+/)?[\w.-]+")

_SPECS = {
    PYPI: re.compile(r"(===?)\s*(\d[\w.+!-]*)"),
    NPM: re.compile(r"([\^~=]?)(\d+\.\d+\.\d+[\w.+-]*)"),
}


@dataclass(frozen=True)
class Upgrade:
    """One manifest line moving a package to a release without known advisories."""

    manifest: str
    line: int
    ecosystem: str
    name: str
    spec: str
    current: str
    target: str
    breaking: bool
    advisories: tuple[str, ...]

    def new_spec(self) -> str:
        match = _SPECS[self.ecosystem].fullmatch(self.spec)
        return f"{match.group(1) if match else ''}{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "advisories": list(self.advisories), "new_spec": self.new_spec()}


def supported_manifest(ecosystem: str, manifest: str) -> bool:
    filename = PurePosixPath(manifest).name.lower()
    if ecosystem == PYPI:
        return filename.startswith("requirements") and filename.endswith(".txt")
    return ecosystem == NPM and filename == "package.json"


def _target(dependency: dict[str, Any]) -> tuple[str, bool]:
    fix = dependency.get("remediation")
    fix = fix if isinstance(fix, dict) else {}
    if fix.get("non_breaking_target"):
        target, breaking = str(fix["non_breaking_target"]), False
    else:
        target, breaking = str(fix.get("target") or ""), bool(fix.get("breaking"))
    if _VERSION.fullmatch(target) is None or target == str(dependency.get("version") or ""):
        return "", False
    return target, breaking


def _rewritable(dependency: dict[str, Any]) -> bool:
    ecosystem = str(dependency.get("ecosystem") or "")
    if _NAME.fullmatch(str(dependency.get("name") or "")) is None:
        return False
    if not (dependency.get("direct") and supported_manifest(ecosystem, str(dependency.get("manifest") or ""))):
        return False
    return _SPECS[ecosystem].fullmatch(str(dependency.get("spec") or "").strip()) is not None


def _advisory_ids(dependency: dict[str, Any]) -> tuple[str, ...]:
    raw = dependency.get("vulnerabilities")
    return tuple(str(item.get("id") if isinstance(item, dict) else item) for item in raw if item) if isinstance(raw, list) else ()


def _upgrade(dependency: dict[str, Any]) -> Upgrade | None:
    target, breaking = _target(dependency)
    if not (target and _rewritable(dependency)):
        return None
    return Upgrade(
        manifest=str(dependency["manifest"]),
        line=int(dependency.get("line") or 0),
        ecosystem=str(dependency["ecosystem"]),
        name=str(dependency.get("name") or ""),
        spec=str(dependency["spec"]).strip(),
        current=str(dependency.get("version") or ""),
        target=target,
        breaking=breaking,
        advisories=_advisory_ids(dependency),
    )


def plan_upgrades(report: dict[str, Any] | None) -> list[Upgrade]:
    """Upgrades for every vulnerable direct dependency with a rewritable declaration."""
    raw = (report or {}).get("dependencies")
    planned: dict[tuple[str, int, str], Upgrade] = {}
    for dependency in raw if isinstance(raw, list) else []:
        upgrade = _upgrade(dependency) if isinstance(dependency, dict) else None
        if upgrade is not None and upgrade.line > 0:
            identity = (upgrade.manifest, upgrade.line, normalize_package(upgrade.ecosystem, upgrade.name))
            planned.setdefault(identity, upgrade)
    return sorted(planned.values(), key=lambda item: (item.manifest, item.line, item.name))


def _declaration(upgrade: Upgrade) -> re.Pattern[str]:
    spec = re.escape(upgrade.spec)
    if upgrade.ecosystem == NPM:
        return re.compile(rf'("{re.escape(upgrade.name)}"\s*:\s*"){spec}(")')
    name = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", upgrade.name))
    return re.compile(rf"^(\s*{name}\s*(?:\[[^\]]*\])?\s*){spec}(?=\s*(?:;|#|$))", re.IGNORECASE)


def _replacement(spec: str):
    return lambda match: f"{match.group(1)}{spec}{match.group(2) if match.lastindex == 2 else ''}"


def apply_upgrades(text: str, upgrades: list[Upgrade]) -> tuple[str, list[Upgrade]]:
    """
    Rewrite each upgrade's declaration on its line.

    A line that no longer declares the scanned spec (the file changed since
    the scan) is left alone and that upgrade is not reported as applied.
    """
    lines = text.splitlines(keepends=True)
    applied = []
    for upgrade in upgrades:
        index = upgrade.line - 1
        if not 0 <= index < len(lines):
            continue
        changed, count = _declaration(upgrade).subn(
            _replacement(upgrade.new_spec()),
            lines[index],
            count=1,
        )
        if count:
            lines[index] = changed
            applied.append(upgrade)
    return "".join(lines), applied
