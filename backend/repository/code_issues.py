"""Shared types and file selection for first-party code security checks."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from backend.risk.confidence import FIRM
from backend.rules.generic.clientside import SECRET_PATTERNS

TEST_DIRECTORIES = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "testdata", "test-data", "fixtures", "__fixtures__", "__mocks__", "e2e"}
)
_TEST_FILE = re.compile(
    r"(?:^test_.*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[jt]sx?$|(?:Test|Tests|Spec)\.(?:java|kt|cs|scala)$|_spec\.rb$)"
)
SUPPRESSION = re.compile(r"secguard-ignore|\bnosec\b", re.IGNORECASE)


@dataclass
class SecurityIssue:
    rule_id: str
    path: str
    line: int
    message: str
    snippet: str = ""
    confidence: str = FIRM
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part.lower() in TEST_DIRECTORIES for part in parts[:-1]) or bool(_TEST_FILE.search(parts[-1] if parts else ""))


def suppressed(line: str) -> bool:
    return bool(SUPPRESSION.search(line))


def snippet(line: str) -> str:
    text = line.strip()
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text if len(text) <= 160 else text[:157] + "..."
