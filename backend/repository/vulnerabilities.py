"""
Known vulnerabilities for resolved dependencies, from the OSV database
(https://osv.dev), and the smallest upgrade that clears them.
"""

from __future__ import annotations

import functools
import math
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

from backend.repository.manifests import Dependency, normalize_package
from backend.repository.versions import compare, is_breaking_upgrade

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

BATCH_SIZE = 500

Poster = Callable[[str, dict[str, Any]], Any]
Fetcher = Callable[[str], Any]


def http_poster(url: str, payload: dict[str, Any]) -> Any:
    try:
        response = requests.post(url, json=payload, timeout=30)
        return response.json() if response.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None


@dataclass
class Vulnerability:
    id: str
    package: str
    ecosystem: str
    version: str
    summary: str = ""
    severity: str = "medium"
    cvss: float | None = None
    aliases: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    minimum_fix: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["url"] = self.url
        return data


# ------------------------------------------------------------- CVSS v3.x

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _round_up(value: float) -> float:
    integer = round(value * 100000)

    if integer % 10000 == 0:
        return integer / 100000.0

    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a CVSS v3.0/v3.1 vector, per the FIRST specification."""

    if not vector.startswith("CVSS:3"):
        return None

    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])

        changed = metrics["S"] == "C"

        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]

        impact_base = 1 - (
            (1 - _WEIGHTS["C"][metrics["C"]])
            * (1 - _WEIGHTS["I"][metrics["I"]])
            * (1 - _WEIGHTS["A"][metrics["A"]])
        )

        exploitability = (
            8.22
            * _WEIGHTS["AV"][metrics["AV"]]
            * _WEIGHTS["AC"][metrics["AC"]]
            * privileges
            * _WEIGHTS["UI"][metrics["UI"]]
        )
    except (KeyError, ValueError):
        return None

    if changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_base

    if impact <= 0:
        return 0.0

    if changed:
        return _round_up(min(1.08 * (impact + exploitability), 10))

    return _round_up(min(impact + exploitability, 10))


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


_GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


# ---------------------------------------------------------- range logic


def _ranges_for(record: dict[str, Any], dependency: Dependency) -> list[list[dict[str, str]]]:
    wanted = normalize_package(dependency.ecosystem, dependency.name)
    ranges = []

    for affected in record.get("affected") or []:
        if not _affected_package_matches(affected, dependency, wanted):
            continue
        ranges.extend(_supported_ranges(affected))

    return ranges


def _supported_ranges(affected: dict[str, Any]) -> list[list[dict[str, str]]]:
    return [
        list(entry.get("events") or [])
        for entry in affected.get("ranges") or []
        if entry.get("type") in ("ECOSYSTEM", "SEMVER")
    ]


def _affected_package_matches(
    affected: dict[str, Any],
    dependency: Dependency,
    wanted: str,
) -> bool:
    package = affected.get("package") or {}
    if package.get("ecosystem", "").split(":")[0] != dependency.ecosystem:
        return False

    name = normalize_package(dependency.ecosystem, str(package.get("name") or ""))
    return name == wanted


def _affected_by(ranges: list[list[dict[str, str]]], ecosystem: str, version: str) -> bool:
    for events in ranges:
        if _events_affect_version(events, ecosystem, version):
            return True

    return False


def _events_affect_version(
    events: list[dict[str, str]],
    ecosystem: str,
    version: str,
) -> bool:
    introduced = None

    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        elif introduced is not None and (
            "fixed" in event or "last_affected" in event
        ):
            if _bounded_range_affects(introduced, event, ecosystem, version):
                return True
            introduced = None

    return introduced is not None and (
        introduced == "0" or compare(ecosystem, version, introduced) >= 0
    )


def _bounded_range_affects(
    introduced: str,
    event: dict[str, str],
    ecosystem: str,
    version: str,
) -> bool:
    upper = event.get("fixed") or event.get("last_affected")
    lower_matches = introduced == "0" or compare(ecosystem, version, introduced) >= 0
    upper_comparison = compare(ecosystem, version, upper)
    upper_matches = (
        upper_comparison <= 0
        if "last_affected" in event
        else upper_comparison < 0
    )
    return lower_matches and upper_matches


def _fixed_versions(ranges: list[list[dict[str, str]]]) -> list[str]:
    return sorted({event["fixed"] for events in ranges for event in events if event.get("fixed")})


def _sorted(ecosystem: str, versions: list[str]) -> list[str]:
    return sorted(versions, key=functools.cmp_to_key(lambda a, b: compare(ecosystem, a, b)))


def _parse(record: dict[str, Any], dependency: Dependency) -> Vulnerability | None:
    if record.get("withdrawn"):
        return None

    ranges = _ranges_for(record, dependency)
    fixed, later = _fixed_and_later(ranges, dependency)
    database = record.get("database_specific") or {}
    cvss = _cvss_score(record)
    severity = _vulnerability_severity(database, cvss)

    return Vulnerability(
        id=str(record.get("id")),
        package=dependency.name,
        ecosystem=dependency.ecosystem,
        version=dependency.version,
        summary=str(record.get("summary") or record.get("details") or "")[:300],
        severity=severity,
        cvss=cvss,
        aliases=list(record.get("aliases") or []),
        cwes=list(database.get("cwe_ids") or []),
        fixed=fixed,
        minimum_fix=_minimum_fix(later),
        references=_reference_urls(record),
    )


def _fixed_and_later(
    ranges: list[list[dict[str, str]]],
    dependency: Dependency,
) -> tuple[list[str], list[str]]:
    fixed = _sorted(dependency.ecosystem, _fixed_versions(ranges))
    later = [
        version
        for version in fixed
        if compare(dependency.ecosystem, version, dependency.version) > 0
    ]
    return fixed, later


def _minimum_fix(later: list[str]) -> str:
    return later[0] if later else ""


def _reference_urls(record: dict[str, Any]) -> list[str]:
    return [
        str(item.get("url"))
        for item in (record.get("references") or [])[:5]
        if item.get("url")
    ]


def _cvss_score(record: dict[str, Any]) -> float | None:
    for entry in record.get("severity") or []:
        if entry.get("type") == "CVSS_V3":
            return cvss3_base_score(str(entry.get("score") or ""))
    return None


def _vulnerability_severity(database: dict[str, Any], cvss: float | None) -> str:
    severity = _GHSA_SEVERITY.get(str(database.get("severity") or "").upper())
    if severity:
        return severity
    return severity_from_cvss(cvss) if cvss is not None else "medium"


@dataclass
class Remediation:
    """The smallest single upgrade that clears every known advisory."""

    target: str = ""
    breaking: bool = False
    non_breaking_target: str = ""
    resolves_all: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def remediation(
    dependency: Dependency,
    vulnerabilities: list[Vulnerability],
    ranges: dict[str, list[list[dict[str, str]]]],
) -> Remediation:
    ecosystem = dependency.ecosystem

    candidates = _sorted(
        ecosystem,
        sorted(
            {
                version
                for vulnerability in vulnerabilities
                for version in vulnerability.fixed
                if compare(ecosystem, version, dependency.version) > 0
            }
        ),
    )

    def clears(version: str) -> bool:
        return not any(_affected_by(ranges[item.id], ecosystem, version) for item in vulnerabilities)

    target = next((version for version in candidates if clears(version)), "")

    non_breaking = next(
        (
            version
            for version in candidates
            if not is_breaking_upgrade(ecosystem, dependency.version, version) and clears(version)
        ),
        "",
    )

    return Remediation(
        target=target,
        breaking=bool(target) and is_breaking_upgrade(ecosystem, dependency.version, target),
        non_breaking_target=non_breaking,
        resolves_all=bool(target),
    )


def _query_vulnerability_ids(
    dependencies: list[Dependency], post: Poster
) -> dict[int, list[str]]:
    checkable = [
        (index, dependency)
        for index, dependency in enumerate(dependencies)
        if dependency.version
    ]

    identifiers: dict[int, list[str]] = {}

    for start in range(0, len(checkable), BATCH_SIZE):
        chunk = checkable[start:start + BATCH_SIZE]

        response = post(
            OSV_BATCH,
            {
                "queries": [
                    {
                        "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
                        "version": dependency.version,
                    }
                    for _, dependency in chunk
                ]
            },
        )

        results = (response or {}).get("results") or []

        for (index, _), result in zip(chunk, results):
            ids = [str(item.get("id")) for item in (result or {}).get("vulns") or [] if item.get("id")]

            if ids:
                identifiers[index] = ids
    return identifiers


def _resolve_dependency_vulnerabilities(
    dependency: Dependency,
    identifiers: list[str],
    records: dict[str, dict[str, Any]],
    fetch: Fetcher,
) -> tuple[list[Vulnerability], Remediation | None]:
    parsed = []
    ranges = {}
    seen: set[str] = set()
    # Prefer reviewed GitHub advisories over their PYSEC/CVE aliases.
    ordered = sorted(identifiers, key=lambda value: (not value.startswith("GHSA-"), value))
    for identifier in ordered:
        if identifier in seen:
            continue
        if identifier not in records:
            records[identifier] = fetch(OSV_VULN + identifier) or {}
        record = records[identifier]
        vulnerability = _parse(record, dependency)
        if vulnerability is None:
            continue
        names = {vulnerability.id, *vulnerability.aliases}
        if names & seen:
            seen.update(names)
            continue
        seen.update(names)
        parsed.append(vulnerability)
        ranges[vulnerability.id] = _ranges_for(record, dependency)
    return parsed, remediation(dependency, parsed, ranges) if parsed else None


def find_vulnerabilities(
    dependencies: list[Dependency],
    post: Poster | None = http_poster,
    fetch: Fetcher | None = None,
) -> tuple[dict[int, list[Vulnerability]], dict[int, Remediation]]:
    """
    Advisories per dependency (keyed by list index) and the remediation
    for each vulnerable one. ``post=None`` disables lookups entirely.
    """
    if post is None:
        return {}, {}
    fetch = fetch or (lambda url: _get(url))
    identifiers = _query_vulnerability_ids(dependencies, post)
    records: dict[str, dict[str, Any]] = {}
    found: dict[int, list[Vulnerability]] = {}
    remediations: dict[int, Remediation] = {}
    for index, ids in identifiers.items():
        parsed, fix = _resolve_dependency_vulnerabilities(
            dependencies[index], ids, records, fetch
        )
        if parsed and fix is not None:
            found[index] = parsed
            remediations[index] = fix

    return found, remediations


def _get(url: str) -> Any:
    try:
        response = requests.get(url, timeout=30)
        return response.json() if response.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None
