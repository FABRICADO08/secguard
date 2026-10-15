"""
Maintainability rating in the style of the ISO/IEC 25010 model used by
Sigrid: seven system properties, each rated 0.5-5.5 stars from a risk
profile, averaged into one rating.

Thresholds approximate the published SIG/TÜViT calibration; a property
that cannot be measured (for example module coupling for a language
without resolvable imports) is left out of the average.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from backend.repository.units import Unit

# Value at which each property drops below 5, 4, 3 and 2 stars.
VOLUME_KLOC = (66, 246, 665, 1310)
DUPLICATION_PERCENT = (3, 5, 10, 20)
GINI = (0.4, 0.55, 0.7, 0.85)


@dataclass(frozen=True)
class Profile:
    """Risk categories (lower bounds, exclusive) and the share allowed per star band."""

    bounds: tuple[int, int, int]
    limits: tuple[tuple[float, float, float], ...]


UNIT_SIZE = Profile((15, 30, 60), ((19.5, 10.9, 3.9), (26.0, 15.5, 6.5), (34.1, 22.2, 11.0), (45.9, 31.4, 18.1)))
UNIT_COMPLEXITY = Profile((5, 10, 25), ((21.0, 7.0, 1.5), (30.0, 13.0, 4.5), (38.0, 19.0, 9.5), (50.0, 28.0, 16.0)))
UNIT_INTERFACING = Profile((2, 4, 6), ((12.0, 5.5, 2.2), (15.0, 7.5, 3.2), (18.0, 10.0, 5.0), (25.0, 15.0, 7.0)))
MODULE_COUPLING = Profile((10, 20, 50), ((23.0, 10.0, 4.0), (32.0, 15.0, 7.0), (42.0, 22.0, 12.0), (55.0, 32.0, 20.0)))

_SOURCE_ROOTS = frozenset({"src", "lib", "app", "source", "sources", "pkg", "internal"})


def stars(value: float, thresholds: Sequence[float]) -> float:
    """Linear 5.5 (value 0) to 0.5 rating, crossing 4.5/3.5/2.5/1.5 at each threshold."""
    points = [0.0, *thresholds, thresholds[-1] * 2]
    for index in range(len(points) - 1):
        low, high = points[index], points[index + 1]
        if value <= high:
            return round(5.5 - index - (value - low) / ((high - low) or 1), 2)
    return 0.5


def profile_rating(weights: Iterable[tuple[float, float]], profile: Profile) -> dict[str, Any] | None:
    """Rate ``(metric, weight)`` pairs: the worst category decides the rating."""
    shares = [0.0, 0.0, 0.0]
    total = 0.0
    for metric, weight in weights:
        total += weight
        for category, bound in enumerate(profile.bounds):
            if metric > bound:
                shares[category] += weight
    if not total:
        return None
    percents = [round(100 * share / total, 1) for share in shares]
    rating = min(
        stars(percent, [limit[category] for limit in profile.limits])
        for category, percent in enumerate(percents)
    )
    return {"rating": round(rating, 1), "profile": dict(zip(("moderate", "high", "very_high"), percents))}


def _scalar(value: float, thresholds: Sequence[float], **details: Any) -> dict[str, Any]:
    return {"rating": round(stars(value, thresholds), 1), **details}


def component_of(path: str) -> str:
    parts = path.split("/")
    if len(parts) > 2 and parts[0] in _SOURCE_ROOTS:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if len(parts) > 1 else "(root)"


def gini(sizes: Sequence[int]) -> float:
    ordered = sorted(sizes)
    total = sum(ordered)
    if len(ordered) < 2 or not total:
        return 0.0
    weighted = sum((index + 1) * size for index, size in enumerate(ordered))
    return round((2 * weighted) / (len(ordered) * total) - (len(ordered) + 1) / len(ordered), 3)


def component_balance(file_lines: dict[str, int]) -> dict[str, Any] | None:
    components: dict[str, int] = {}
    for path, lines in file_lines.items():
        components[component_of(path)] = components.get(component_of(path), 0) + lines
    if not components or not sum(components.values()):
        return None
    inequality = gini(list(components.values()))
    rating = stars(inequality, GINI)
    if len(components) == 1 or len(components) > 20:
        rating -= 1
    return {"rating": round(max(rating, 0.5), 1), "components": len(components), "gini": inequality}


def module_coupling(imports: dict[str, set[str]], file_lines: dict[str, int]) -> dict[str, Any] | None:
    fan_in = {path: 0 for path in imports}
    for targets in imports.values():
        for target in targets:
            fan_in[target] = fan_in.get(target, 0) + 1
    return profile_rating(((count, file_lines.get(path, 0)) for path, count in fan_in.items()), MODULE_COUPLING)


def maintainability_rating(
    units: list[Unit],
    file_lines: dict[str, int],
    duplicated_lines: int,
    imports: dict[str, set[str]],
) -> dict[str, Any]:
    code_lines = sum(file_lines.values())
    properties: dict[str, dict[str, Any] | None] = {
        "volume": _scalar(code_lines / 1000, VOLUME_KLOC, lines=code_lines) if code_lines else None,
        "duplication": _scalar(100 * duplicated_lines / code_lines, DUPLICATION_PERCENT,
                               percent=round(100 * duplicated_lines / code_lines, 1)) if code_lines else None,
        "unit_size": profile_rating(((unit.lines, unit.lines) for unit in units), UNIT_SIZE),
        "unit_complexity": profile_rating(((unit.complexity, unit.lines) for unit in units), UNIT_COMPLEXITY),
        "unit_interfacing": profile_rating(((unit.parameters, 1) for unit in units), UNIT_INTERFACING),
        "module_coupling": module_coupling(imports, file_lines) if imports else None,
        "component_balance": component_balance(file_lines),
    }
    rated = [value["rating"] for value in properties.values() if value]
    return {
        "rating": round(sum(rated) / len(rated), 1) if rated else None,
        "units": len(units),
        "properties": properties,
    }
