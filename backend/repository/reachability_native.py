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

# NuGet ID prefixes whose namespaces are named differently.
NUGET_NAMESPACES = {"awssdk": "amazon", "awssdk.core": "amazon.runtime", "bouncycastle.cryptography": "org.bouncycastle"}

# NuGet packages that plug into a framework and are usually configured rather than imported.
NUGET_PLUGIN_MARKERS = (".sinks.", ".aspnetcore.", ".extensions.", ".dependencyinjection.", ".analyzers.", ".runtime.")

# Module prefixes (lower case) of Swift packages whose products are not named after the repository.
SWIFT_MODULES = {
    "github.com/apple/swift-collections": {"collections", "orderedcollections", "dequemodule", "heapmodule", "bitcollections", "hashtreecollections"},
    "github.com/apple/swift-log": {"logging"},
    "github.com/apple/swift-argument-parser": {"argumentparser"},
    "github.com/apple/swift-nio": {"nio"},
    "github.com/apple/swift-crypto": {"crypto", "_cryptoextras"},
    "github.com/firebase/firebase-ios-sdk": {"firebase"},
    "github.com/realm/realm-swift": {"realm"},
    "github.com/airbnb/lottie-ios": {"lottie"},
    "github.com/pointfreeco/swift-composable-architecture": {"composablearchitecture"},
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


def _nuget_namespace(package: str) -> str:
    """The root namespace a package is expected to provide (``AWSSDK.S3`` -> ``amazon.s3``)."""
    package = package.lower()
    for prefix, namespace in NUGET_NAMESPACES.items():
        if package == prefix or package.startswith(prefix + "."):
            return namespace + package[len(prefix):]
    return package


def nuget_reachable(package: str, namespaces: set[str]) -> bool | None:
    """A package provides its own name as a namespace (``Newtonsoft.Json`` -> ``Newtonsoft.Json.Linq``).

    None when the package plugs into a framework (sinks, ASP.NET Core and DI extensions) or shares
    a root namespace with imported code, since such packages are often used without their own ``using``.
    """
    expected = _nuget_namespace(package)
    lowered = {item.lower() for item in namespaces}
    if any(_provides(expected, namespace) for namespace in lowered):
        return True
    roots = {namespace.split(".")[0] for namespace in lowered}
    plugin = any(marker in f"{expected}." for marker in NUGET_PLUGIN_MARKERS)
    return None if plugin or expected.split(".")[0] in roots else False


def _provides(expected: str, namespace: str) -> bool:
    if namespace == expected or namespace.startswith(expected + "."):
        return True
    return "." in namespace and expected.startswith(namespace + ".")


def _under(imports: set[str], prefixes: Iterable[str]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for name in imports for prefix in prefixes)


def maven_reachable(coordinate: str, imports: set[str]) -> bool | None:
    """Whether code imports a Java package of ``group:artifact``.

    A group holds several artifacts, so an import under the group alone is not attributed to one
    of them (None); the artifact's own package (``org.apache.commons.lang3`` for commons-lang3,
    ``com.fasterxml.jackson.databind`` for jackson-databind) is. Starters and BOMs are None.
    """
    group, _, artifact = coordinate.partition(":")
    if "starter" in artifact or artifact.endswith("-bom"):
        return None
    if coordinate in MAVEN_PACKAGES:
        return _under(imports, MAVEN_PACKAGES[coordinate])
    if _under(imports, _artifact_packages(group, artifact)):
        return True
    return None if _under(imports, [group]) else False


def _artifact_packages(group: str, artifact: str) -> list[str]:
    """``org.apache.commons:commons-lang3`` -> ``org.apache.commons.lang3``…, plus ``<parent group>.<last token>``."""
    last = group.rsplit(".", 1)[-1]
    tokens = [token for token in re.split(r"[-_.]", artifact) if token and token != last]
    parent = group.rpartition(".")[0]
    sibling = [f"{parent}.{tokens[-1]}"] if parent and tokens else []
    return [f"{group}.{token}" for token in tokens] + sibling


def cargo_reachable(crate: str, crates: set[str]) -> bool:
    return crate.replace("-", "_") in crates


def pub_reachable(package: str, packages: set[str]) -> bool | None:
    return None if package in DART_TOOLING else package in packages


def _module_candidates(name: str) -> set[str]:
    base = name.lower()
    for affix in ("swift-", "-swift", ".swift", "-ios", "_ios"):
        base = base.removeprefix(affix) if affix.endswith("-") else base.removesuffix(affix)
    return {base.replace("-", "").replace("_", ""), base.replace("-", "_")}


def swift_reachable(identity: str, modules: set[str]) -> bool | None:
    """``github.com/apple/swift-nio`` provides ``NIO``, ``NIOCore``…: match the repository name as a module prefix.

    Products need not be named after the repository, so a package without a known product list
    whose name matches no import is None rather than not imported.
    """
    known = SWIFT_MODULES.get(identity.lower().removesuffix("/"))
    candidates = known or {item for item in _module_candidates(identity.rstrip("/").rsplit("/", 1)[-1]) if len(item) >= 3}
    if any(module.startswith(candidate) for module in modules for candidate in candidates):
        return True
    return False if known else None


def pod_reachable(pod: str, modules: set[str]) -> bool:
    """``Firebase/Analytics`` is imported as ``Firebase`` or ``FirebaseAnalytics``."""
    root, _, subspec = pod.partition("/")
    candidates = _module_candidates(root) | (_module_candidates(root + subspec) if subspec else set())
    return bool(candidates & modules)
