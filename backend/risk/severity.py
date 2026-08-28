from __future__ import annotations

from collections.abc import Iterable
from typing import Any

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFORMATIONAL = "informational"


SEVERITIES = (
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFORMATIONAL,
)


SEVERITY_ORDER = {
    INFORMATIONAL: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
}


BASE_SCORES = {
    INFORMATIONAL: 5,
    LOW: 20,
    MEDIUM: 45,
    HIGH: 70,
    CRITICAL: 90,
}


_ALIASES = {
    "info": INFORMATIONAL,
    "informational": INFORMATIONAL,
    "note": INFORMATIONAL,
    "none": INFORMATIONAL,
    "low": LOW,
    "moderate": MEDIUM,
    "medium": MEDIUM,
    "warning": MEDIUM,
    "high": HIGH,
    "important": HIGH,
    "critical": CRITICAL,
    "severe": CRITICAL,
    "blocker": CRITICAL,
}


def normalize_severity(value: Any) -> str:
    """Map an arbitrary severity label onto the canonical scale."""

    return _ALIASES.get(
        str(value or "").strip().lower(),
        INFORMATIONAL,
    )


def severity_rank(value: Any) -> int:
    return SEVERITY_ORDER[normalize_severity(value)]


def base_score(value: Any) -> int:
    return BASE_SCORES[normalize_severity(value)]


def severity_from_score(score: float) -> str:
    if score >= 85:
        return CRITICAL

    if score >= 65:
        return HIGH

    if score >= 40:
        return MEDIUM

    if score >= 20:
        return LOW

    return INFORMATIONAL


def highest_severity(values: Iterable[Any]) -> str:
    highest = INFORMATIONAL

    for value in values:
        if severity_rank(value) > severity_rank(highest):
            highest = normalize_severity(value)

    return highest


def empty_severity_counts() -> dict[str, int]:
    return {severity: 0 for severity in SEVERITIES}
