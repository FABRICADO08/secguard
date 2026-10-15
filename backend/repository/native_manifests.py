"""
Manifest and lockfile parsers for .NET, Gradle, Rust, Dart/Flutter, Swift
and CocoaPods projects.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any
from xml.etree import ElementTree

from backend.repository.dependency import DEVELOPMENT, RUNTIME, Dependency, line_of
from backend.repository.versions import (
    CARGO,
    COCOAPODS,
    MAVEN,
    NUGET,
    PUB,
    SWIFT,
    is_exact,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


# ---------------------------------------------------------------- .NET


def _xml_root(text: str):
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None


def _local_name(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _child_text(element, name: str) -> str:
    for child in element:
        if _local_name(child.tag) == name:
            return (child.text or "").strip()

    return ""


def _nuget_version(spec: str) -> str:
    exact = re.fullmatch(r"\[\s*([^,\]\s]+)\s*\]", spec)

    if exact:
        return exact.group(1)

    return spec if is_exact(spec) else ""


def parse_msbuild(text: str, manifest: str) -> list[Dependency]:
    """
    Parse NuGet references from project files and central package props.

    A central ``PackageVersion`` is treated like a lockfile entry so that a
    versionless ``PackageReference`` borrows its version.
    """
    root = _xml_root(text)

    if root is None:
        return []

    dependencies = []

    for element in root.iter():
        kind = _local_name(element.tag)
        name = element.get("Include") or element.get("Update") or ""

        if kind not in ("PackageReference", "PackageVersion") or not name:
            continue

        spec = element.get("VersionOverride") or element.get("Version") or _child_text(element, "Version")
        dependencies.append(
            Dependency(
                name=name,
                ecosystem=NUGET,
                version=_nuget_version(spec),
                spec=spec,
                manifest=manifest,
                line=line_of(text, f'"{name}"'),
                direct=kind == "PackageReference",
            )
        )

    return dependencies


def parse_packages_config(text: str, manifest: str) -> list[Dependency]:
    """Parse legacy NuGet packages.config entries."""
    root = _xml_root(text)

    if root is None:
        return []

    return [
        Dependency(
            name=element.get("id", ""),
            ecosystem=NUGET,
            version=element.get("version", ""),
            spec=element.get("version", ""),
            manifest=manifest,
            line=line_of(text, f'"{element.get("id")}"'),
            scope=DEVELOPMENT if element.get("developmentDependency") == "true" else RUNTIME,
        )
        for element in root.iter()
        if _local_name(element.tag) == "package" and element.get("id")
    ]


def parse_nuget_lock(text: str, manifest: str) -> list[Dependency]:
    """Parse resolved packages from a NuGet packages.lock.json."""
    try:
        frameworks = json.loads(text).get("dependencies") or {}
    except (json.JSONDecodeError, AttributeError):
        return []

    return [
        Dependency(name=name, ecosystem=NUGET, version=str(entry["resolved"]), manifest=manifest, direct=False)
        for packages in frameworks.values()
        if isinstance(packages, dict)
        for name, entry in packages.items()
        if isinstance(entry, dict) and entry.get("resolved") and entry.get("type") != "Project"
    ]


# ---------------------------------------------------------------- Gradle

_GRADLE_CONFIGURATIONS = (
    "implementation",
    "api",
    "compileonly",
    "runtimeonly",
    "classpath",
    "annotationprocessor",
    "kapt",
    "ksp",
    "compile",
    "runtime",
)

_GRADLE_STRING = re.compile(
    r"""\b(\w+)\s*\(?\s*['"]([\w.-]+):([\w.-]+):([^'"@:\s]+)[^'"]*['"]"""
)

_GRADLE_MAP = re.compile(
    r"""\b(\w+)\s*\(?\s*group\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*name\s*[:=]\s*['"]([^'"]+)['"]"""
    r"""\s*,\s*version\s*[:=]\s*['"]([^'"]+)['"]"""
)


def _gradle_scope(configuration: str) -> str:
    return DEVELOPMENT if configuration.lower().startswith(("test", "androidtest")) else RUNTIME


def _gradle_dependency(name: str, spec: str, manifest: str, line: int, scope: str = RUNTIME) -> Dependency:
    resolved = "" if "$" in spec else spec

    return Dependency(
        name=name,
        ecosystem=MAVEN,
        version=resolved if is_exact(resolved) else "",
        spec=spec,
        manifest=manifest,
        line=line,
        scope=scope,
    )


def parse_gradle(text: str, manifest: str) -> list[Dependency]:
    """Parse string and map dependency notations from Groovy or Kotlin build scripts."""
    dependencies = []

    for number, line in enumerate(text.splitlines(), start=1):
        for pattern in (_GRADLE_STRING, _GRADLE_MAP):
            for configuration, group, artifact, spec in pattern.findall(line):
                if configuration.lower().endswith(_GRADLE_CONFIGURATIONS):
                    dependencies.append(
                        _gradle_dependency(
                            f"{group}:{artifact}", spec, manifest, number, _gradle_scope(configuration)
                        )
                    )

    return dependencies


def _catalog_module(entry: dict[str, Any]) -> str:
    if entry.get("module"):
        return str(entry["module"])

    if entry.get("group") and entry.get("name"):
        return f"{entry['group']}:{entry['name']}"

    return ""


def _catalog_version(entry: dict[str, Any], versions: dict[str, Any]) -> str:
    version = entry.get("version", "")
    reference = version.get("ref") if isinstance(version, dict) else entry.get("version.ref")

    if reference:
        version = versions.get(reference, "")

    if isinstance(version, dict):
        version = version.get("strictly") or version.get("require") or ""

    return str(version)


def _catalog_entry(entry: Any, versions: dict[str, Any]) -> tuple[str, str]:
    if isinstance(entry, str):
        parts = entry.split(":")
        return (":".join(parts[:2]), parts[2]) if len(parts) == 3 else ("", "")

    if not isinstance(entry, dict):
        return ("", "")

    return (_catalog_module(entry), _catalog_version(entry, versions))


def parse_gradle_catalog(text: str, manifest: str) -> list[Dependency]:
    """Parse libraries from a Gradle version catalog (libs.versions.toml)."""
    try:
        catalog = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    versions = catalog.get("versions") or {}
    dependencies = []

    for alias, entry in (catalog.get("libraries") or {}).items():
        module, version = _catalog_entry(entry, versions)

        if module:
            dependencies.append(_gradle_dependency(module, version, manifest, line_of(text, alias)))

    return dependencies


def parse_gradle_lockfile(text: str, manifest: str) -> list[Dependency]:
    """Parse resolved coordinates from a gradle.lockfile."""
    dependencies = []

    for raw in text.splitlines():
        match = re.fullmatch(r"([\w.-]+):([\w.-]+):([^=\s]+)=(.*)", raw.strip())

        if match:
            configurations = [item for item in match.group(4).split(",") if item]
            development = bool(configurations) and all(_gradle_scope(item) == DEVELOPMENT for item in configurations)
            dependencies.append(
                Dependency(
                    name=f"{match.group(1)}:{match.group(2)}",
                    ecosystem=MAVEN,
                    version=match.group(3),
                    manifest=manifest,
                    direct=False,
                    scope=DEVELOPMENT if development else RUNTIME,
                )
            )

    return dependencies


# ---------------------------------------------------------------- Rust

_CARGO_SECTIONS = {
    "dependencies": RUNTIME,
    "build-dependencies": RUNTIME,
    "dev-dependencies": DEVELOPMENT,
}


def _cargo_tables(document: dict[str, Any]):
    tables = [document, document.get("workspace") or {}]
    tables.extend(target for target in (document.get("target") or {}).values() if isinstance(target, dict))

    for table in tables:
        for section, scope in _CARGO_SECTIONS.items():
            if isinstance(table.get(section), dict):
                yield table[section], scope


def _cargo_dependency(key: str, value: Any, scope: str, text: str, manifest: str) -> Dependency | None:
    if isinstance(value, dict):
        if not value.get("version") and (value.get("path") or value.get("git") or value.get("workspace")):
            return None
        name = str(value.get("package") or key)
        spec = str(value.get("version") or "")
    else:
        name, spec = key, str(value)

    pinned = spec.strip().startswith("=")

    return Dependency(
        name=name,
        ecosystem=CARGO,
        version=spec.strip().lstrip("=").strip() if pinned else "",
        spec=spec,
        manifest=manifest,
        line=line_of(text, key),
        scope=scope,
    )


def parse_cargo_toml(text: str, manifest: str) -> list[Dependency]:
    """Parse crates.io dependencies declared in a Cargo.toml."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    return [
        dependency
        for table, scope in _cargo_tables(document)
        for key, value in table.items()
        if (dependency := _cargo_dependency(key, value, scope, text, manifest))
    ]


_CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}


def parse_cargo_lock(text: str, manifest: str) -> list[Dependency]:
    """Parse crates resolved from crates.io in a Cargo.lock."""
    try:
        packages = tomllib.loads(text).get("package") or []
    except tomllib.TOMLDecodeError:
        return []

    return [
        Dependency(name=str(item["name"]), ecosystem=CARGO, version=str(item["version"]), manifest=manifest, direct=False)
        for item in packages
        if isinstance(item, dict)
        and item.get("name")
        and item.get("version")
        and item.get("source") in _CRATES_IO_SOURCES
    ]


# ---------------------------------------------------------------- Dart / Flutter

_PUB_SECTIONS = {"dependencies": RUNTIME, "dev_dependencies": DEVELOPMENT}
_YAML_ENTRY = re.compile(r"^(\s+)([A-Za-z0-9_]+):\s*(.*)$")


def _yaml_lines(text: str):
    for number, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"\s+#.*$", "", raw).rstrip()

        if line.strip() and not line.lstrip().startswith("#"):
            yield number, line


class _PubspecReader:
    def __init__(self, manifest: str) -> None:
        self.manifest = manifest
        self.found: list[Dependency] = []
        self.local: set[int] = set()
        self.scope: str | None = None
        self.indent = 0

    def feed(self, number: int, line: str) -> None:
        if not line.startswith((" ", "\t")):
            self.scope = _PUB_SECTIONS.get(line.split(":")[0].strip())
            self.indent = 0
            return

        match = _YAML_ENTRY.match(line)

        if self.scope is None or match is None:
            return

        depth, key, value = len(match.group(1)), match.group(2), match.group(3).strip().strip("'\"")
        self.indent = self.indent or depth

        if depth == self.indent:
            self.found.append(
                Dependency(
                    name=key,
                    ecosystem=PUB,
                    version=value if is_exact(value) else "",
                    spec=value,
                    manifest=self.manifest,
                    line=number,
                    scope=self.scope,
                )
            )
        elif self.found:
            self._nested(key, value)

    def _nested(self, key: str, value: str) -> None:
        current = self.found[-1]

        if key in ("sdk", "path", "git"):
            self.local.add(id(current))
        elif key == "version":
            current.spec = value
            current.version = value if is_exact(value) else ""

    def dependencies(self) -> list[Dependency]:
        return [item for item in self.found if id(item) not in self.local]


def parse_pubspec(text: str, manifest: str) -> list[Dependency]:
    """Parse hosted dependencies from a pubspec.yaml."""
    reader = _PubspecReader(manifest)

    for number, line in _yaml_lines(text):
        reader.feed(number, line)

    return reader.dependencies()


def _pub_lock_entries(text: str):
    in_packages = False

    for _, line in _yaml_lines(text):
        if not line.startswith(" "):
            in_packages = line.strip() == "packages:"
            continue

        match = _YAML_ENTRY.match(line)

        if in_packages and match:
            yield len(match.group(1)), match.group(2), match.group(3).strip().strip("'\"")


def _pub_lock_packages(text: str) -> dict[str, dict[str, str]]:
    packages: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None

    for depth, key, value in _pub_lock_entries(text):
        if depth == 2:
            current = packages.setdefault(key, {})
        elif depth == 4 and current is not None:
            current[key] = value

    return packages


def parse_pubspec_lock(text: str, manifest: str) -> list[Dependency]:
    """Parse hosted packages resolved in a pubspec.lock."""
    packages = _pub_lock_packages(text)

    return [
        Dependency(
            name=name,
            ecosystem=PUB,
            version=fields["version"],
            manifest=manifest,
            direct=False,
            scope=DEVELOPMENT if fields.get("dependency") == "direct dev" else RUNTIME,
        )
        for name, fields in packages.items()
        if fields.get("source") == "hosted" and fields.get("version")
    ]


# ---------------------------------------------------------------- Swift / iOS

_SWIFT_PACKAGE = re.compile(
    r'\.package\(\s*(?:name:\s*"[^"]*"\s*,\s*)?url:\s*"([^"]+)"\s*,\s*'
    r'(?:([.\w]+)\s*[:(]\s*)?(?:from:\s*)?"([^"]+)"'
)

_SWIFT_VERSIONED = (None, "from", "exact", ".exact", ".upToNextMajor", ".upToNextMinor")


def swift_identity(location: str) -> str:
    """The OSV ``SwiftURL`` name of a package: its URL without scheme or ``.git``."""
    location = re.sub(r"^git@([^:]+):", r"\1/", location.strip())
    location = re.sub(r"^[a-z+]+://", "", location)

    return location.removesuffix("/").removesuffix(".git")


def parse_package_swift(text: str, manifest: str) -> list[Dependency]:
    """Parse URL-based package requirements from a Package.swift."""
    return [
        Dependency(
            name=swift_identity(match.group(1)),
            ecosystem=SWIFT,
            version=match.group(3) if match.group(2) in ("exact", ".exact") else "",
            spec=match.group(3),
            manifest=manifest,
            line=text.count("\n", 0, match.start()) + 1,
        )
        for match in _SWIFT_PACKAGE.finditer(text)
        if match.group(2) in _SWIFT_VERSIONED
    ]


def parse_package_resolved(text: str, manifest: str) -> list[Dependency]:
    """Parse pinned versions from a SwiftPM Package.resolved (v1 to v3)."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []

    if not isinstance(document, dict):
        return []

    pins = document.get("pins") or (document.get("object") or {}).get("pins") or []

    return [dependency for pin in pins if (dependency := _swift_pin(pin, manifest))]


def _swift_pin(pin: Any, manifest: str) -> Dependency | None:
    if not isinstance(pin, dict) or not isinstance(pin.get("state"), dict):
        return None

    location = pin.get("location") or pin.get("repositoryURL")
    version = pin["state"].get("version")

    if not location or not version:
        return None

    return Dependency(
        name=swift_identity(str(location)),
        ecosystem=SWIFT,
        version=str(version),
        manifest=manifest,
        direct=False,
    )


_PODFILE_POD = re.compile(r"""^\s*pod\s+['"]([^'"/]+)[^'"]*['"]\s*(?:,\s*['"]([^'"]+)['"])?""")


def parse_podfile(text: str, manifest: str) -> list[Dependency]:
    """Parse pod declarations from a CocoaPods Podfile."""
    dependencies = []

    for number, line in enumerate(text.splitlines(), start=1):
        match = _PODFILE_POD.match(line)

        if match:
            spec = (match.group(2) or "").strip()
            dependencies.append(
                Dependency(
                    name=match.group(1),
                    ecosystem=COCOAPODS,
                    version=spec if is_exact(spec) else "",
                    spec=spec,
                    manifest=manifest,
                    line=number,
                )
            )

    return dependencies


def parse_podfile_lock(text: str, manifest: str) -> list[Dependency]:
    """Parse resolved pods (subspecs folded into their pod) from a Podfile.lock."""
    resolved: dict[str, str] = {}
    in_pods = False

    for raw in text.splitlines():
        if raw and not raw.startswith(" "):
            in_pods = raw.strip() == "PODS:"
            continue

        match = re.fullmatch(r"  - ([^\s(/]+)(?:/[^\s(]*)? \(([^)]+)\):?", raw)

        if in_pods and match:
            resolved.setdefault(match.group(1), match.group(2))

    return [
        Dependency(name=name, ecosystem=COCOAPODS, version=version, manifest=manifest, direct=False)
        for name, version in resolved.items()
    ]

