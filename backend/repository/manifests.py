"""
Find and parse dependency manifests and lockfiles in a repository.

Manifests (requirements.txt, package.json, ...) say what a project asks
for and where it is declared; lockfiles say which exact release was
resolved. Both are read so that a finding can point at the line a
developer would edit while still naming the version actually installed.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from backend.repository.versions import (
    GO,
    MAVEN,
    NPM,
    PACKAGIST,
    PYPI,
    RUBYGEMS,
    is_exact,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "bower_components",
        "site-packages",
        "__pycache__",
        "dist",
        "build",
        "vendor",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
    }
)

MAX_MANIFEST_BYTES = 10 * 1024 * 1024

RUNTIME = "runtime"
DEVELOPMENT = "development"

_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;#]*)"
)


@dataclass
class Dependency:
    name: str
    ecosystem: str
    version: str = ""
    spec: str = ""
    manifest: str = ""
    line: int = 0
    direct: bool = True
    scope: str = RUNTIME
    resolved_from_range: bool = False

    def key(self) -> tuple[str, str]:
        return (self.ecosystem, normalize_package(self.ecosystem, self.name))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_package(ecosystem: str, name: str) -> str:
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()

    if ecosystem in (NPM, PACKAGIST, RUBYGEMS):
        return name.lower()

    return name


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        if any(part in SKIPPED_DIRECTORIES for part in relative.parts[:-1]):
            continue

        if path.is_file():
            yield path


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        return ""

    return path.read_text(encoding="utf-8", errors="replace")


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number

    return 0


def _pin_from_spec(spec: str) -> str:
    match = re.fullmatch(r"\s*===?\s*([^\s,*]+)\s*", spec)

    return match.group(1) if match else ""


# ---------------------------------------------------------------- Python


def parse_requirements(text: str, manifest: str) -> list[Dependency]:
    dependencies = []

    scope = DEVELOPMENT if re.search(r"dev|test|lint", manifest, re.IGNORECASE) else RUNTIME

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()

        if not line or line.startswith(("#", "-", "git+", "http:", "https:")):
            continue

        match = _REQUIREMENT.match(line)

        if match is None:
            continue

        spec = match.group(3).strip()

        dependencies.append(
            Dependency(
                name=match.group(1),
                ecosystem=PYPI,
                version=_pin_from_spec(spec),
                spec=spec,
                manifest=manifest,
                line=number,
                scope=scope,
            )
        )

    return dependencies


def _pep508(requirement: str) -> tuple[str, str]:
    match = _REQUIREMENT.match(requirement)

    if match is None:
        return ("", "")

    return (match.group(1), match.group(3).strip())


def parse_pyproject(text: str, manifest: str) -> list[Dependency]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    dependencies = []

    project = document.get("project") or {}

    groups: list[tuple[str, list[Any]]] = [
        (RUNTIME, list(project.get("dependencies") or []))
    ]

    for name, items in (project.get("optional-dependencies") or {}).items():
        scope = DEVELOPMENT if re.search(r"dev|test|lint|doc", name, re.IGNORECASE) else RUNTIME
        groups.append((scope, list(items or [])))

    for scope, items in groups:
        for item in items:
            name, spec = _pep508(str(item))

            if name:
                dependencies.append(
                    Dependency(
                        name=name,
                        ecosystem=PYPI,
                        version=_pin_from_spec(spec),
                        spec=spec,
                        manifest=manifest,
                        line=_line_of(text, str(item)),
                        scope=scope,
                    )
                )

    poetry = (document.get("tool") or {}).get("poetry") or {}

    poetry_groups = [(RUNTIME, poetry.get("dependencies") or {}),
                     (DEVELOPMENT, poetry.get("dev-dependencies") or {})]

    for name, group in (poetry.get("group") or {}).items():
        poetry_groups.append(
            (
                RUNTIME if name == "main" else DEVELOPMENT,
                (group or {}).get("dependencies") or {},
            )
        )

    for scope, table in poetry_groups:
        for name, value in table.items():
            if name.lower() == "python":
                continue

            spec = value.get("version", "") if isinstance(value, dict) else str(value)

            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=PYPI,
                    version=spec if is_exact(spec) else _pin_from_spec(spec),
                    spec=spec,
                    manifest=manifest,
                    line=_line_of(text, f"{name} ="),
                    scope=scope,
                )
            )

    return dependencies


def parse_poetry_lock(text: str, manifest: str) -> list[Dependency]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    return [
        Dependency(
            name=str(package.get("name")),
            ecosystem=PYPI,
            version=str(package.get("version") or ""),
            manifest=manifest,
            direct=False,
            scope=DEVELOPMENT if package.get("category") == "dev" else RUNTIME,
        )
        for package in document.get("package") or []
        if package.get("name")
    ]


def parse_pipfile_lock(text: str, manifest: str) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    dependencies = []

    for section, scope in (("default", RUNTIME), ("develop", DEVELOPMENT)):
        for name, entry in (document.get(section) or {}).items():
            version = _pin_from_spec(str((entry or {}).get("version") or ""))

            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=PYPI,
                    version=version,
                    manifest=manifest,
                    direct=False,
                    scope=scope,
                )
            )

    return dependencies


# ------------------------------------------------------------ JavaScript


def parse_package_json(text: str, manifest: str) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    dependencies = []

    for section, scope in (
        ("dependencies", RUNTIME),
        ("optionalDependencies", RUNTIME),
        ("peerDependencies", RUNTIME),
        ("devDependencies", DEVELOPMENT),
    ):
        for name, spec in (document.get(section) or {}).items():
            spec = str(spec)

            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=NPM,
                    version=spec if re.fullmatch(r"\d+\.\d+\.\d+\S*", spec) else "",
                    spec=spec,
                    manifest=manifest,
                    line=_line_of(text, f'"{name}"'),
                    scope=scope,
                )
            )

    return dependencies


def parse_package_lock(text: str, manifest: str) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    dependencies = []

    packages = document.get("packages")

    if isinstance(packages, dict):
        for location, entry in packages.items():
            if not location or "node_modules/" not in location:
                continue

            name = entry.get("name") or location.rsplit("node_modules/", 1)[1]

            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=NPM,
                    version=str(entry.get("version") or ""),
                    manifest=manifest,
                    direct=False,
                    scope=DEVELOPMENT if entry.get("dev") else RUNTIME,
                )
            )

        return dependencies

    def walk(tree: dict[str, Any]) -> None:
        for name, entry in tree.items():
            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=NPM,
                    version=str(entry.get("version") or ""),
                    manifest=manifest,
                    direct=False,
                    scope=DEVELOPMENT if entry.get("dev") else RUNTIME,
                )
            )

            walk(entry.get("dependencies") or {})

    walk(document.get("dependencies") or {})

    return dependencies


# ------------------------------------------------------- other ecosystems


def parse_go_mod(text: str, manifest: str) -> list[Dependency]:
    dependencies = []

    in_block = False

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if line.startswith("require ("):
            in_block = True
            continue

        if in_block and line == ")":
            in_block = False
            continue

        if line.startswith("require "):
            line = line[len("require "):]
        elif not in_block:
            continue

        parts = line.split()

        if len(parts) >= 2:
            dependencies.append(
                Dependency(
                    name=parts[0],
                    ecosystem=GO,
                    version=parts[1],
                    spec=parts[1],
                    manifest=manifest,
                    line=number,
                    direct="// indirect" not in line,
                )
            )

    return dependencies


def parse_pom(text: str, manifest: str) -> list[Dependency]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []

    namespace = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    properties = {
        element.tag.replace(namespace, ""): (element.text or "").strip()
        for element in root.findall(f"{namespace}properties/*")
    }
    return [
        dependency
        for element in root.iter(f"{namespace}dependency")
        if (dependency := _parse_pom_dependency(element, namespace, properties, text, manifest))
    ]


def _parse_pom_dependency(
    element,
    namespace: str,
    properties: dict[str, str],
    text: str,
    manifest: str,
) -> Dependency | None:
    group = (element.findtext(f"{namespace}groupId") or "").strip()
    artifact = (element.findtext(f"{namespace}artifactId") or "").strip()
    version = (element.findtext(f"{namespace}version") or "").strip()
    scope = (element.findtext(f"{namespace}scope") or "").strip()

    reference = re.fullmatch(r"\$\{([^}]+)\}", version)

    if reference:
        version = properties.get(reference.group(1), "")

    if not group or not artifact:
        return None
    return Dependency(
        name=f"{group}:{artifact}",
        ecosystem=MAVEN,
        version=version,
        spec=version,
        manifest=manifest,
        line=_line_of(text, f"<artifactId>{artifact}</artifactId>"),
        scope=DEVELOPMENT if scope == "test" else RUNTIME,
    )


def parse_composer_lock(text: str, manifest: str) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    return [
        Dependency(
            name=str(package.get("name")),
            ecosystem=PACKAGIST,
            version=str(package.get("version") or "").lstrip("v"),
            manifest=manifest,
            direct=False,
            scope=scope,
        )
        for section, scope in (("packages", RUNTIME), ("packages-dev", DEVELOPMENT))
        for package in document.get(section) or []
        if package.get("name")
    ]


def parse_gemfile_lock(text: str, manifest: str) -> list[Dependency]:
    dependencies = []

    in_specs = False

    for raw in text.splitlines():
        if raw.strip() == "specs:":
            in_specs = True
            continue

        if in_specs and raw and not raw.startswith(" "):
            in_specs = False

        match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", raw)

        if in_specs and match:
            dependencies.append(
                Dependency(
                    name=match.group(1),
                    ecosystem=RUBYGEMS,
                    version=match.group(2).split("-")[0],
                    manifest=manifest,
                    direct=False,
                )
            )

    return dependencies


PARSERS = (
    (re.compile(r"(^|/)requirements[^/]*\.(txt|in)$"), parse_requirements),
    (re.compile(r"(^|/)pyproject\.toml$"), parse_pyproject),
    (re.compile(r"(^|/)poetry\.lock$"), parse_poetry_lock),
    (re.compile(r"(^|/)Pipfile\.lock$"), parse_pipfile_lock),
    (re.compile(r"(^|/)package\.json$"), parse_package_json),
    (re.compile(r"(^|/)package-lock\.json$"), parse_package_lock),
    (re.compile(r"(^|/)npm-shrinkwrap\.json$"), parse_package_lock),
    (re.compile(r"(^|/)go\.mod$"), parse_go_mod),
    (re.compile(r"(^|/)pom\.xml$"), parse_pom),
    (re.compile(r"(^|/)composer\.lock$"), parse_composer_lock),
    (re.compile(r"(^|/)Gemfile\.lock$"), parse_gemfile_lock),
)


def _merge(found: list[Dependency]) -> list[Dependency]:
    """
    One entry per (ecosystem, package, version).

    A declared dependency without a pin borrows the version its lockfile
    resolved, so it can be checked for advisories while still pointing at
    the manifest line. Lockfile-only packages are transitive.
    """

    declared = [dependency for dependency in found if dependency.direct]
    locked = [dependency for dependency in found if not dependency.direct]

    resolved: dict[tuple[str, str], set[str]] = {}

    for dependency in locked:
        if dependency.version:
            resolved.setdefault(dependency.key(), set()).add(dependency.version)

    merged: dict[tuple[str, str, str], Dependency] = {}
    _merge_declared(declared, resolved, merged)
    _merge_locked(locked, merged)

    return sorted(
        merged.values(),
        key=lambda item: (item.ecosystem, normalize_package(item.ecosystem, item.name), item.version),
    )


def _merge_declared(
    declared: list[Dependency],
    resolved: dict[tuple[str, str], set[str]],
    merged: dict[tuple[str, str, str], Dependency],
) -> None:
    for dependency in declared:
        versions = resolved.get(dependency.key(), set())
        if not dependency.version and len(versions) == 1:
            dependency.version = next(iter(versions))

        identity = (*dependency.key(), dependency.version)
        current = merged.get(identity)
        if current is None or (
            current.scope == DEVELOPMENT and dependency.scope == RUNTIME
        ):
            merged[identity] = dependency


def _merge_locked(
    locked: list[Dependency],
    merged: dict[tuple[str, str, str], Dependency],
) -> None:
    for dependency in locked:
        if not dependency.version:
            continue
        identity = (*dependency.key(), dependency.version)
        if identity not in merged:
            merged[identity] = dependency


def discover_dependencies(root: Path) -> list[Dependency]:
    found: list[Dependency] = []

    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()

        for pattern, parser in PARSERS:
            if pattern.search(relative):
                found.extend(parser(_read(path), relative))
                break

    return _merge(found)
