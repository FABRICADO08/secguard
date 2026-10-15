"""First-party code security: injection, unsafe deserialization, weak transport and hard-coded secrets."""

from __future__ import annotations

from pathlib import Path

from backend.repository.code_issues import SecurityIssue, is_test_path
from backend.repository.code_patterns import pattern_issues
from backend.repository.code_python import python_issues
from backend.repository.code_secrets import (
    history_secrets,
    scans_for_secrets,
    tree_secrets,
)
from backend.repository.manifests import iter_files
from backend.repository.quality import MAX_SOURCE_BYTES, SOURCE_SUFFIXES

SUFFIXES = frozenset(SOURCE_SUFFIXES)


def _code_issues(relative: str, text: str, language: str) -> list[SecurityIssue]:
    if is_test_path(relative):
        return []
    return python_issues(relative, text) if language == "Python" else pattern_issues(relative, text, language)


def _scan_file(path: Path, relative: str, current: set[str]) -> list[SecurityIssue]:
    language = SOURCE_SUFFIXES.get(path.suffix.lower(), "")
    secrets = scans_for_secrets(relative, SUFFIXES)
    if not (language or secrets) or path.stat().st_size > MAX_SOURCE_BYTES:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    issues = _code_issues(relative, text, language) if language else []
    if secrets:
        found, values = tree_secrets(relative, text)
        issues += found
        current.update(values)
    return issues


def analyse_code_security(root: Path, history: bool = True) -> list[SecurityIssue]:
    current: set[str] = set()
    issues: list[SecurityIssue] = []
    for path in iter_files(root):
        issues += _scan_file(path, path.relative_to(root).as_posix(), current)
    if history:
        issues += history_secrets(root, current, SUFFIXES)
    return issues
