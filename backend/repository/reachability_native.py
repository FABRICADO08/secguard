"""
Import-level reachability for .NET, JVM (Maven/Gradle), Rust, Dart, Swift
and CocoaPods dependencies: which namespaces, packages, crates and modules
the project's own source files import, and whether a dependency provides one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from backend.repository.manifests import iter_files

DOTNET_SUFFIXES = (".cs", ".fs", ".fsx", ".vb", ".cshtml", ".razor")
JVM_SUFFIXES = (".java", ".kt", ".kts", ".scala", ".groovy")
APPLE_SUFFIXES = (".swift", ".m", ".mm", ".h")

_DOTNET_IMPORT = re.compile(
    r"^\s*@?(?:global\s+)?(?:using|open|Imports)\s+(?:static\s+)?(?:\w+\s*=\s*)?([A-Za-z_][\w.]*)",
    re.MULTILINE,
)
_JVM_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([a-zA-Z_][\w.]*)", re.MULTILINE)
_RUST_PATH = re.compile(r"\b(?:extern\s+crate\s+|use\s+::?)?([a-z_][a-z0-9_]*)::|\bextern\s+crate\s+([a-z0-9_]+)")
_DART_IMPORT = re.compile(r"""(?:import|export|part)\s+['"]package:([a-z0-9_]+)/""")
_SWIFT_IMPORT = re.compile(
    r"^\s*(?:@testable\s+|@_exported\s+|@_implementationOnly\s+)?import\s+(?:(?:class|struct|enum|protocol|func|var|let|typealias)\s+)?(\w+)",
    re.MULTILINE,
)
_OBJC_IMPORT = re.compile(r"""^\s*(?:#import\s*<(\w+)/|#include\s*<(\w+)/|@import\s+(\w+))""", re.MULTILINE)

# Maven artifacts whose Java package does not start with their groupId.
MAVEN_PACKAGES = {
    "com.google.guava:guava": ["com.google.common"],
    "junit:junit": ["org.junit"],
    "org.projectlombok:lombok": ["lombok"],
    "commons-io:commons-io": ["org.apache.commons.io"],
    "commons-codec:commons-codec": ["org.apache.commons.codec"],
    "commons-collections:commons-collections": ["org.apache.commons.collections"],
    "commons-lang:commons-lang": ["org.apache.commons.lang"],
    "org.yaml:snakeyaml": ["org.yaml.snakeyaml"],
    "com.squareup.okhttp3:okhttp": ["okhttp3"],
    "com.squareup.retrofit2:retrofit": ["retrofit2"],
    "org.jetbrains.kotlinx:kotlinx-coroutines-core": ["kotlinx.coroutines"],
}

# Dart packages used by tools, code generation or the SDK rather than imported.
DART_TOOLING = frozenset(
    {"build_runner", "flutter_lints", "lints", "json_serializable", "freezed",
     "flutter_launcher_icons", "flutter_native_splash", "very_good_analysis", "injectable_generator"}
)


def _matches(pattern: re.Pattern[str], suffixes: tuple[str, ...], root: Path) -> Iterable[str]:
    for path in iter_files(root):
        if path.suffix in suffixes:
            for match in pattern.finditer(path.read_text(encoding="utf-8", errors="replace")):
                yield next(group for group in match.groups() if group)


def dotnet_namespaces(root: Path) -> set[str]:
    return set(_matches(_DOTNET_IMPORT, DOTNET_SUFFIXES, root))


def jvm_imports(root: Path) -> set[str]:
    return set(_matches(_JVM_IMPORT, JVM_SUFFIXES, root))


def rust_crates(root: Path) -> set[str]:
    return set(_matches(_RUST_PATH, (".rs",), root))


def dart_packages(root: Path) -> set[str]:
    return set(_matches(_DART_IMPORT, (".dart",), root))


def apple_modules(root: Path) -> set[str]:
    swift = _matches(_SWIFT_IMPORT, (".swift",), root)
    objc = _matches(_OBJC_IMPORT, (".m", ".mm", ".h"), root)
    return {module.lower() for module in [*swift, *objc]}


def nuget_reachable(package: str, namespaces: set[str]) -> bool:
    """A package provides its own name as a namespace (``Newtonsoft.Json`` -> ``Newtonsoft.Json.Linq``)."""
    package = package.lower()
    for namespace in (item.lower() for item in namespaces):
        if namespace == package or namespace.startswith(package + "."):
            return True
        if namespace.count(".") >= 1 and package.startswith(namespace + "."):
            return True
    return False


def maven_reachable(coordinate: str, imports: set[str]) -> bool | None:
    """Whether code imports a Java package of ``group:artifact``; None when it is a starter or BOM."""
    group, _, artifact = coordinate.partition(":")
    if "starter" in artifact or artifact.endswith("-bom"):
        return None
    prefixes = MAVEN_PACKAGES.get(coordinate) or [group, f"{group.rpartition('.')[0]}.{artifact.split('-')[-1]}"]
    return any(name == prefix or name.startswith(prefix + ".") for name in imports for prefix in prefixes)


def cargo_reachable(crate: str, crates: set[str]) -> bool:
    return crate.replace("-", "_") in crates


def pub_reachable(package: str, packages: set[str]) -> bool | None:
    return None if package in DART_TOOLING else package in packages


def _module_candidates(name: str) -> set[str]:
    base = name.lower()
    for affix in ("swift-", "-swift", ".swift", "-ios", "_ios"):
        base = base.removeprefix(affix) if affix.endswith("-") else base.removesuffix(affix)
    return {base.replace("-", "").replace("_", ""), base.replace("-", "_")}


def swift_reachable(identity: str, modules: set[str]) -> bool:
    """``github.com/apple/swift-nio`` provides ``NIO``, ``NIOCore``…: match the repository name as a module prefix."""
    candidates = {item for item in _module_candidates(identity.rstrip("/").rsplit("/", 1)[-1]) if len(item) >= 3}
    return any(module.startswith(candidate) for module in modules for candidate in candidates)


def pod_reachable(pod: str, modules: set[str]) -> bool:
    """``Firebase/Analytics`` is imported as ``Firebase`` or ``FirebaseAnalytics``."""
    root, _, subspec = pod.partition("/")
    candidates = _module_candidates(root) | (_module_candidates(root + subspec) if subspec else set())
    return bool(candidates & modules)
