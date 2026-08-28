from __future__ import annotations

from typing import Any

CONFIRMED = "confirmed"
FIRM = "firm"
TENTATIVE = "tentative"


CONFIDENCES = (
    CONFIRMED,
    FIRM,
    TENTATIVE,
)


CONFIDENCE_MULTIPLIERS = {
    CONFIRMED: 1.0,
    FIRM: 0.85,
    TENTATIVE: 0.6,
}


_ALIASES = {
    "confirmed": CONFIRMED,
    "certain": CONFIRMED,
    "high": CONFIRMED,
    "firm": FIRM,
    "medium": FIRM,
    "probable": FIRM,
    "tentative": TENTATIVE,
    "low": TENTATIVE,
    "possible": TENTATIVE,
}


def normalize_confidence(value: Any) -> str:
    """Map an arbitrary confidence label onto the canonical scale."""

    return _ALIASES.get(
        str(value or "").strip().lower(),
        FIRM,
    )


def confidence_multiplier(value: Any) -> float:
    return CONFIDENCE_MULTIPLIERS[normalize_confidence(value)]
