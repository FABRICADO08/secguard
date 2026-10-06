"""
Import-level reachability: whether the project's own code imports a
dependency at all.

This is deliberately coarse. A package that is never imported cannot
have its vulnerable functions called from first-party code (it may still
be loaded by another dependency), so advisories against it are lowered
in confidence rather than dropped. Function-level call-graph analysis is
not attempted.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from backend.repository.manifests import Dependency, iter_files, normalize_package
from backend.repository.versions import GO, NPM, PYPI

IMPORTED = "imported"
NOT_IMPORTED = "not-imported"
TRANSITIVE = "transitive"
UNKNOWN = "unknown"

# Distributions whose import name differs from the package name.
PYTHON_IMPORT_NAMES = {
    "beautifulsoup4": ["bs4"],
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"],
    "python-dotenv": ["dotenv"],
    "pyjwt": ["jwt"],
    "psycopg2-binary": ["psycopg2"],
    "opencv-python": ["cv2"],
    "protobuf": ["google.protobuf", "google"],
    "pyopenssl": ["OpenSSL"],
    "dnspython": ["dns"],
    "attrs": ["attr", "attrs"],
    "msgpack-python": ["msgpack"],
    "pymysql": ["pymysql"],
    "typing-extensions": ["typing_extensions"],
    "charset-normalizer": ["charset_normalizer"],
    "google-api-python-client": ["googleapiclient"],
    "pycryptodome": ["Crypto"],
    "kafka-python": ["kafka"],
    "markdown": ["markdown"],
}

# Packages that are tools or plugins, used without being imported.
TOOLING = frozenset(
    {"gunicorn", "uvicorn", "pytest", "coverage", "tox", "ruff", "black", "flake8",
     "mypy", "pip", "setuptools", "wheel", "eslint", "prettier", "typescript",
     "nodemon", "webpack", "webpack-cli", "vite", "jest", "mocha", "babel-core"}
)

_JS_IMPORT = re.compile(
    r"""(?:require\(\s*|import\(\s*|from\s+|import\s+)['"]([^'"./][^'"]*)['"]"""
)


def _python_modules(root: Path) -> set[str]:
    modules: set[str] = set()

    for path in iter_files(root):
        if path.suffix != ".py":
            continue

        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    modules.update(".".join(parts[: index + 1]) for index in range(len(parts)))
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                parts = node.module.split(".")
                modules.update(".".join(parts[: index + 1]) for index in range(len(parts)))

    return modules


def _js_packages(root: Path) -> set[str]:
    packages: set[str] = set()

    for path in iter_files(root):
        if path.suffix not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"):
            continue

        for match in _JS_IMPORT.finditer(path.read_text(encoding="utf-8", errors="replace")):
            specifier = match.group(1)
            parts = specifier.split("/")
            packages.add("/".join(parts[:2]) if specifier.startswith("@") else parts[0])

    return packages


def _go_imports(root: Path) -> set[str]:
    imports: set[str] = set()

    for path in iter_files(root):
        if path.suffix == ".go":
            imports.update(re.findall(r'"([\w.-]+\.[\w.-]+/[^"]+)"', path.read_text(encoding="utf-8", errors="replace")))

    return imports


class ReachabilityIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._python: set[str] | None = None
        self._js: set[str] | None = None
        self._go: set[str] | None = None

    @property
    def python(self) -> set[str]:
        if self._python is None:
            self._python = _python_modules(self.root)
        return self._python

    @property
    def js(self) -> set[str]:
        if self._js is None:
            self._js = _js_packages(self.root)
        return self._js

    @property
    def go(self) -> set[str]:
        if self._go is None:
            self._go = _go_imports(self.root)
        return self._go

    def status(self, dependency: Dependency) -> str:
        name = normalize_package(dependency.ecosystem, dependency.name)

        if name in TOOLING:
            return UNKNOWN

        if dependency.ecosystem == PYPI:
            candidates = PYTHON_IMPORT_NAMES.get(name) or [
                name.replace("-", "_"),
                name.removeprefix("python-").replace("-", "_"),
                name.replace("-", "."),
            ]
            found = any(candidate in self.python for candidate in candidates)

        elif dependency.ecosystem == NPM:
            # Type declarations are consumed by the compiler, never imported.
            if name.startswith("@types/"):
                return UNKNOWN

            found = name in self.js

        elif dependency.ecosystem == GO:
            found = any(path == dependency.name or path.startswith(dependency.name + "/") for path in self.go)

        else:
            return UNKNOWN

        if found:
            return IMPORTED

        return NOT_IMPORTED if dependency.direct else TRANSITIVE
