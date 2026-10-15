"""
Language-neutral units (functions/methods) and local module imports, the
raw material for the maintainability rating.

Python is measured from its AST elsewhere; brace languages are measured
heuristically here by matching a function header to its closing brace.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

BRACE_LANGUAGES = frozenset(
    {"JavaScript", "TypeScript", "Java", "Kotlin", "Go", "PHP", "C#", "Scala", "Swift", "Rust", "C", "C++"}
)

_CONTROL = frozenset({"if", "for", "while", "switch", "catch", "return", "function", "else", "do", "try", "new", "using", "lock", "foreach", "sizeof", "typeof"})

_HEADERS = (
    re.compile(r"\b(?:func|fun|fn|function|def)\s+\*?(?:\([^)]*\)\s*)?([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(([^)]*)\)"),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?(?:function\s*\*?\s*)?\(([^)]*)\)\s*(?:=>)?"),
    re.compile(r"^\s*(?:[\w$<>\[\],.?*&:@]+\s+)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?:const\s*)?(?:throws\s+[\w., ]+)?\s*(?::\s*[\w<>\[\],.? |]+)?\s*\{"),
)

_STRINGS = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`")
_LINE_COMMENT = re.compile(r"//.*$")
_BRANCHES = re.compile(r"\b(?:if|for|foreach|while|case|catch|guard|match)\b|&&|\|\||\?\?")


@dataclass
class Unit:
    path: str
    name: str
    line: int
    lines: int
    complexity: int
    parameters: int


def _clean(line: str) -> str:
    return _LINE_COMMENT.sub("", _STRINGS.sub('""', line))


def _header(line: str) -> tuple[str, str] | None:
    for pattern in _HEADERS:
        match = pattern.search(line)
        if match and match.group(1) not in _CONTROL:
            return match.group(1), match.group(2)
    return None


def _parameter_count(arguments: str) -> int:
    flat = re.sub(r"<[^<>]*>", "", arguments)
    return sum(1 for part in flat.split(",") if part.strip() and part.strip() != "void")


def _body_end(lines: list[str], start: int) -> int | None:
    """Index of the line closing the first brace opened at or after ``start``."""
    depth = 0
    opened = False
    for index in range(start, len(lines)):
        for character in lines[index]:
            if character == "{":
                depth += 1
                opened = True
            elif character == "}" and opened:
                depth -= 1
                if depth == 0:
                    return index
        if not opened and index > start + 2:
            return None
    return None


def brace_units(path: str, text: str) -> list[Unit]:
    lines = [_clean(line) for line in text.splitlines()]
    units: list[Unit] = []
    index = 0
    while index < len(lines):
        found = _header(lines[index])
        end = _body_end(lines, index) if found else None
        if found is None or end is None:
            index += 1
            continue
        body = lines[index:end + 1]
        complexity = 1 + sum(len(_BRANCHES.findall(line)) for line in body)
        units.append(Unit(path, found[0], index + 1, end - index + 1, complexity, _parameter_count(found[1])))
        index = end + 1
    return units


_PY_IMPORT = re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import\b|import\s+([\w.]+))", re.MULTILINE)
_JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)["'](\.{1,2}/[^"']+)["']""")
_JS_SUFFIXES = ("", ".js", ".ts", ".jsx", ".tsx", ".mjs", "/index.js", "/index.ts")


def _python_candidates(path: str, specifier: str) -> list[str]:
    dots = len(specifier) - len(specifier.lstrip("."))
    module = specifier[dots:].replace(".", "/")
    base = posixpath.dirname(path)
    for _ in range(max(dots - 1, 0)):
        base = posixpath.dirname(base)
    stem = posixpath.join(base, module) if dots else module
    return [f"{stem}.py", f"{stem}/__init__.py"] if stem else []


def import_targets(path: str, text: str, language: str, known: set[str]) -> set[str]:
    """Repository files that ``path`` imports, resolved against ``known`` paths."""
    candidates: list[str] = []
    if language == "Python":
        for match in _PY_IMPORT.finditer(text):
            candidates += _python_candidates(path, match.group(1) or match.group(2))
    elif language in ("JavaScript", "TypeScript"):
        for match in _JS_IMPORT.finditer(text):
            stem = posixpath.normpath(posixpath.join(posixpath.dirname(path), match.group(1)))
            candidates += [stem + suffix for suffix in _JS_SUFFIXES]
    return {candidate for candidate in candidates if candidate in known and candidate != path}
