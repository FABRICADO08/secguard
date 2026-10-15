"""The dependency record shared by every manifest parser."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from backend.repository.versions import NPM, NUGET, PACKAGIST, PYPI, RUBYGEMS

RUNTIME = "runtime"
DEVELOPMENT = "development"


@dataclass
class Dependency:
    """
    A direct or transitive dependency and its source location.

    ``defines`` marks a central version definition (NuGet ``PackageVersion``,
    Gradle catalog entry, Cargo workspace dependency) that only applies to
    references beneath it. ``alias`` is the name a reference uses to look a
    definition up when that differs from the package name.
    """

    name: str
    ecosystem: str
    version: str = ""
    spec: str = ""
    manifest: str = ""
    line: int = 0
    direct: bool = True
    scope: str = RUNTIME
    resolved_from_range: bool = False
    defines: bool = False
    alias: str = ""

    def key(self) -> tuple[str, str]:
        """Return the normalized ecosystem and package identity."""
        return (self.ecosystem, normalize_package(self.ecosystem, self.name))

    def to_dict(self) -> dict[str, Any]:
        """Serialize dependency metadata for scan reports."""
        data = asdict(self)
        data.pop("defines")
        data.pop("alias")
        return data


def normalize_package(ecosystem: str, name: str) -> str:
    """Normalize package spelling according to ecosystem conventions."""
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()

    if ecosystem in (NPM, PACKAGIST, RUBYGEMS, NUGET):
        return name.lower()

    return name


def line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number

    return 0
