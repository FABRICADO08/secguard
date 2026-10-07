"""Version parsing and comparison per package ecosystem."""

from __future__ import annotations

import re
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

PYPI = "PyPI"
NPM = "npm"
GO = "Go"
MAVEN = "Maven"
PACKAGIST = "Packagist"
RUBYGEMS = "RubyGems"

ECOSYSTEMS = (PYPI, NPM, GO, MAVEN, PACKAGIST, RUBYGEMS)

_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[-.]?([0-9A-Za-z.-]+?))?(?:\+[0-9A-Za-z.-]+)?$"
)

EXACT = re.compile(r"^v?\d+(?:\.\d+)*(?:[-.+]?[0-9A-Za-z.-]+)?$")


def _semver_key(value: str) -> tuple[Any, ...]:
    match = _SEMVER.match(value.strip())

    if match is None:
        return ((0, 0, 0, 0), 0, ())

    numbers = tuple(int(part or 0) for part in match.groups()[:4])

    prerelease = match.group(5)

    if not prerelease:
        return (numbers, 1, ())

    # A release sorts after any of its pre-releases; within pre-releases
    # numeric identifiers compare numerically and sort before text.
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in re.split(r"[.-]", prerelease)
        if part
    )

    return (numbers, 0, identifiers)


def version_key(ecosystem: str, value: str) -> tuple[Any, ...]:
    if ecosystem == PYPI:
        try:
            return (Version(value),)
        except InvalidVersion:
            return (Version("0"),)

    return _semver_key(value)


def compare(ecosystem: str, left: str, right: str) -> int:
    a = version_key(ecosystem, left)
    b = version_key(ecosystem, right)

    return (a > b) - (a < b)


def is_prerelease(ecosystem: str, value: str) -> bool:
    if ecosystem == PYPI:
        try:
            return Version(value).is_prerelease
        except InvalidVersion:
            return False

    return _semver_key(value)[1] == 0


def release_parts(ecosystem: str, value: str) -> tuple[int, int, int]:
    """Major, minor and patch numbers, zero where absent."""

    if ecosystem == PYPI:
        try:
            release = Version(value).release + (0, 0, 0)
            return (release[0], release[1], release[2])
        except InvalidVersion:
            return (0, 0, 0)

    numbers = _semver_key(value)[0]

    return (numbers[0], numbers[1], numbers[2])


def is_breaking_upgrade(ecosystem: str, current: str, target: str) -> bool:
    """
    Whether moving from ``current`` to ``target`` crosses a compatibility
    boundary under semantic versioning: the major number, or the minor
    number while the major is still 0.
    """

    old = release_parts(ecosystem, current)
    new = release_parts(ecosystem, target)

    if old[0] != new[0]:
        return True

    return old[0] == 0 and old[1] != new[1]


def is_exact(value: str) -> bool:
    return bool(value) and EXACT.match(value.strip()) is not None


def _npm_range_match(spec: str, version: str) -> bool:
    spec = spec.strip()

    if spec in ("", "*", "latest", "x"):
        return True

    for alternative in spec.split("||"):
        if all(_npm_comparator(part, version) for part in alternative.split()):
            return True

    return False


def _npm_comparator(part: str, version: str) -> bool:
    match = re.match(r"^(\^|~|>=|<=|>|<|=)?v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", part)

    if match is None:
        return False

    operator = match.group(1) or "="
    numbers = [match.group(index) for index in (2, 3, 4)]
    base = tuple(int(value) if value and value.isdigit() else 0 for value in numbers)
    wildcard = [value is None or not value.isdigit() for value in numbers]
    current = release_parts(NPM, version)

    if operator == "^":
        if base[0] > 0 or wildcard[1]:
            return current[0] == base[0] and current >= base
        if base[1] > 0 or wildcard[2]:
            return current[:2] == base[:2] and current >= base
        return current == base

    if operator == "~" or (operator == "=" and any(wildcard)):
        if wildcard[1]:
            return current[0] == base[0]
        return current[:2] == base[:2] and current >= base

    return {
        "=": current == base,
        ">=": current >= base,
        "<=": current <= base,
        ">": current > base,
        "<": current < base,
    }[operator]


def satisfies(ecosystem: str, spec: str, version: str) -> bool:
    """Whether ``version`` is allowed by a manifest range."""

    if ecosystem == PYPI:
        try:
            return SpecifierSet(spec.replace(" ", "")).contains(version, prereleases=False)
        except (InvalidSpecifier, InvalidVersion):
            return False

    if ecosystem == NPM:
        return not is_prerelease(NPM, version) and _npm_range_match(spec, version)

    return False


def newest_satisfying(ecosystem: str, spec: str, versions: list[str]) -> str:
    """The release a fresh install would pick for this range."""

    best = ""

    for version in versions:
        if satisfies(ecosystem, spec, version) and (not best or compare(ecosystem, version, best) > 0):
            best = version

    return best
