"""
Find and parse dependency manifests and lockfiles in a repository.

Manifests (requirements.txt, package.json, ...) say what a project asks
for and where it is declared; lockfiles say which exact release was
resolved. Both are read so that a finding can point at the line a
developer would edit while still naming the version actually installed.
"""

from __future__ import annotations

import dataclasses
import json
import posixpath
import re
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from backend.repository.dependency import (
    DEVELOPMENT,
    RUNTIME,
    Dependency,
    normalize_package,
)
from backend.repository.dependency import line_of as _line_of
from backend.repository.native_manifests import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_gradle,
    parse_gradle_catalog,
    parse_gradle_lockfile,
    parse_msbuild,
    parse_nuget_lock,
    parse_package_resolved,
    parse_package_swift,
    parse_packages_config,
    parse_podfile,
    parse_podfile_lock,
    parse_pubspec,
    parse_pubspec_lock,
)
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
        "obj",
        ".gradle",
        ".build",
        ".dart_tool",
        "Pods",
    }
)

MAX_MANIFEST_BYTES = 10 * 1024 * 1024

_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;#]*)"
)


def iter_files(root: Path):
    """Yield repository files while skipping configured generated directories."""
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


def _pin_from_spec(spec: str) -> str:
    match = re.fullmatch(r"\s*===?\s*([^\s,*]+)\s*", spec)

    return match.group(1) if match else ""


# ---------------------------------------------------------------- Python


def parse_requirements(text: str, manifest: str) -> list[Dependency]:
    """Parse pip requirements and retain each declaration's source line."""
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


def _pep508_dependencies(
    text: str, manifest: str, groups: list[tuple[str, list[Any]]]
) -> list[Dependency]:
    dependencies = []
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
    return dependencies


def _poetry_groups(poetry: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    groups = [
        (RUNTIME, poetry.get("dependencies") or {}),
        (DEVELOPMENT, poetry.get("dev-dependencies") or {}),
    ]
    groups.extend(
        (
            RUNTIME if name == "main" else DEVELOPMENT,
            (group or {}).get("dependencies") or {},
        )
        for name, group in (poetry.get("group") or {}).items()
    )
    return groups


def _poetry_dependencies(
    text: str, manifest: str, poetry: dict[str, Any]
) -> list[Dependency]:
    dependencies = []
    for scope, table in _poetry_groups(poetry):
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


def parse_pyproject(text: str, manifest: str) -> list[Dependency]:
    """Read PEP 621 and Poetry dependency declarations from TOML."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    project = document.get("project") or {}

    groups: list[tuple[str, list[Any]]] = [
        (RUNTIME, list(project.get("dependencies") or []))
    ]

    for name, items in (project.get("optional-dependencies") or {}).items():
        scope = DEVELOPMENT if re.search(r"dev|test|lint|doc", name, re.IGNORECASE) else RUNTIME
        groups.append((scope, list(items or [])))

    poetry = (document.get("tool") or {}).get("poetry") or {}
    return _pep508_dependencies(text, manifest, groups) + _poetry_dependencies(
        text, manifest, poetry
    )


def parse_poetry_lock(text: str, manifest: str) -> list[Dependency]:
    """Parse locked package versions from a Poetry lockfile."""
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
    """Parse locked package versions from a Pipfile lock."""
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
    """Parse direct runtime and development dependencies from package.json."""
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
    """Parse transitive package versions from npm lockfile formats."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    dependencies = []

    def add_dependency(name: str, entry: dict[str, Any]) -> None:
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

    packages = document.get("packages")

    if isinstance(packages, dict):
        for location, entry in packages.items():
            if not location or "node_modules/" not in location:
                continue

            name = entry.get("name") or location.rsplit("node_modules/", 1)[1]
            add_dependency(name, entry)

        return dependencies

    def walk(tree: dict[str, Any]) -> None:
        """Traverse nested npm v1 dependency records."""
        for name, entry in tree.items():
            add_dependency(name, entry)

            walk(entry.get("dependencies") or {})

    walk(document.get("dependencies") or {})

    return dependencies


# ------------------------------------------------------- other ecosystems


def parse_go_mod(text: str, manifest: str) -> list[Dependency]:
    """Parse module requirements from a go.mod document."""
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
    """Parse Maven dependency coordinates and resolve local properties."""
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
    """Parse package records from a Composer lockfile."""
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
    """Parse resolved gem versions from a Gemfile lock."""
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
    (re.compile(r"\.(cs|fs|vb)proj$|(^|/)Directory\.(Packages|Build)\.props$"), parse_msbuild),
    (re.compile(r"(^|/)packages\.config$"), parse_packages_config),
    (re.compile(r"(^|/)packages\.lock\.json$"), parse_nuget_lock),
    (re.compile(r"(^|/)build\.gradle(\.kts)?$"), parse_gradle),
    (re.compile(r"(^|/)libs\.versions\.toml$"), parse_gradle_catalog),
    (re.compile(r"(^|/)gradle\.lockfile$"), parse_gradle_lockfile),
    (re.compile(r"(^|/)Cargo\.toml$"), parse_cargo_toml),
    (re.compile(r"(^|/)Cargo\.lock$"), parse_cargo_lock),
    (re.compile(r"(^|/)pubspec\.yaml$"), parse_pubspec),
    (re.compile(r"(^|/)pubspec\.lock$"), parse_pubspec_lock),
    (re.compile(r"(^|/)Package\.swift$"), parse_package_swift),
    (re.compile(r"(^|/)Package\.resolved$"), parse_package_resolved),
    (re.compile(r"(^|/)Podfile$"), parse_podfile),
    (re.compile(r"(^|/)Podfile\.lock$"), parse_podfile_lock),
)


def _definition_root(manifest: str) -> str:
    root = posixpath.dirname(manifest)

    return posixpath.dirname(root) if posixpath.basename(root) == "gradle" else root


def _root_depth(definition: Dependency) -> int:
    root = _definition_root(definition.manifest)

    return root.count("/") + 1 if root else 0


def _applies_to(definition: Dependency, reference: Dependency) -> bool:
    root = _definition_root(definition.manifest)

    if root and not reference.manifest.startswith(root + "/"):
        return False

    if reference.alias:
        return definition.alias == reference.alias

    return definition.key() == reference.key()


def _resolve_reference(reference: Dependency, definitions: list[Dependency]) -> list[Dependency]:
    """A versionless reference takes the version from the nearest applicable definition(s)."""
    candidates = [item for item in definitions if item.ecosystem == reference.ecosystem and _applies_to(item, reference)]

    if not candidates:
        return [] if reference.alias else [reference]

    depth = max(_root_depth(item) for item in candidates)
    nearest = [item for item in candidates if _root_depth(item) == depth]

    return [
        dataclasses.replace(reference, name=item.name, version=item.version, spec=item.spec, alias="")
        for item in nearest
    ]


def _apply_definitions(found: list[Dependency]) -> list[Dependency]:
    """Attach central version definitions to the references they serve; drop unused definitions."""
    definitions = [item for item in found if item.defines]
    applied: list[Dependency] = []

    for dependency in found:
        if dependency.defines:
            continue

        if dependency.direct and not dependency.spec and not dependency.version:
            applied.extend(_resolve_reference(dependency, definitions))
        else:
            applied.append(dependency)

    return applied


def _merge(found: list[Dependency]) -> list[Dependency]:
    """
    One entry per (ecosystem, package, version).

    A declared dependency without a pin borrows the version its lockfile
    resolved, so it can be checked for advisories while still pointing at
    the manifest line. Lockfile-only packages are transitive.
    """

    found = _apply_definitions(found)
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
    """Find supported manifests, parse them, and merge locked versions."""
    found: list[Dependency] = []

    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()

        for pattern, parser in PARSERS:
            if pattern.search(relative):
                found.extend(parser(_read(path), relative))
                break

    return _merge(found)
