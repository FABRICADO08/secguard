"""Run every repository analysis and assemble one JSON report."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.repository import licenses as licensing
from backend.repository.findings import (
    CONFIRMED,
    FIRM,
    TENTATIVE,
    make_finding,
    quality_finding,
)
from backend.repository.health import health_summary
from backend.repository.manifests import (
    DEVELOPMENT,
    Dependency,
    discover_dependencies,
    normalize_package,
)
from backend.repository.quality import analyse_quality
from backend.repository.reachability import IMPORTED, NOT_IMPORTED, ReachabilityIndex
from backend.repository.registry import (
    Fetcher,
    PackageInfo,
    RepositoryActivity,
    offline_fetcher,
    package_info,
    parse_time,
    repository_activity,
)
from backend.repository.sbom import purl
from backend.repository.typosquat import typosquat_target
from backend.repository.versions import compare, newest_satisfying, release_parts
from backend.repository.vulnerabilities import Poster, find_vulnerabilities
from backend.risk.scoring import summarize

SCHEMA = "secguard.repository-report/1"

UNMAINTAINED_YEARS = 2.0
ABANDONED_YEARS = 4.0
NEW_PACKAGE_DAYS = 90
LOW_ADOPTION_DOWNLOADS = 1000


def _years_between(start: str, end: datetime) -> float | None:
    moment = parse_time(start)

    if moment is None:
        return None

    return max((end - moment).days / 365.25, 0.0)


def _project_license(root: Path) -> str:
    texts: dict[str, str] = {}

    for candidate in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        path = root / candidate

        if path.is_file():
            texts["LICENSE"] = path.read_text(encoding="utf-8", errors="replace")
            break

    package_json = root / "package.json"

    if package_json.is_file():
        try:
            declared = json.loads(package_json.read_text(encoding="utf-8")).get("license")
            if isinstance(declared, str):
                texts["declared"] = declared
        except (ValueError, AttributeError):
            pass

    pyproject = root / "pyproject.toml"

    if "declared" not in texts and pyproject.is_file():
        match = re.search(r'^license\s*=\s*(?:\{\s*text\s*=\s*)?"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.MULTILINE)
        if match:
            texts["declared"] = match.group(1)

    return licensing.project_license(texts)


def _location(dependency: Dependency) -> str:
    if dependency.line:
        return f"{dependency.manifest}:{dependency.line}"

    return dependency.manifest


def _freshness(dependency: Dependency, info: PackageInfo | None) -> dict[str, Any]:
    if info is None or not info.latest or not dependency.version:
        return {}

    current = release_parts(dependency.ecosystem, dependency.version)
    latest = release_parts(dependency.ecosystem, info.latest)

    behind = {"major": max(latest[0] - current[0], 0), "minor": 0, "patch": 0}

    if behind["major"] == 0:
        behind["minor"] = max(latest[1] - current[1], 0)

        if behind["minor"] == 0:
            behind["patch"] = max(latest[2] - current[2], 0)

    libyears = None

    released = parse_time(info.released(dependency.version))
    newest = parse_time(info.released(info.latest) or info.latest_release)

    if released and newest and compare(dependency.ecosystem, info.latest, dependency.version) > 0:
        libyears = round(max((newest - released).days / 365.25, 0.0), 2)

    return {
        "latest": info.latest,
        "behind": behind,
        "libyears": libyears if libyears is not None else 0.0,
        "up_to_date": compare(dependency.ecosystem, dependency.version, info.latest) >= 0,
    }


class RepositoryScanner:
    def __init__(
        self,
        root: Path,
        fetch: Fetcher = offline_fetcher,
        post: Poster | None = None,
        github_fetch: Fetcher | None = None,
        today: datetime | None = None,
    ) -> None:
        self.root = root
        self.fetch = fetch
        self.post = post
        self.github_fetch = github_fetch
        self.today = today or datetime.now(timezone.utc)
        self.reachability = ReachabilityIndex(root)
        self._info: dict[tuple[str, str], PackageInfo | None] = {}
        self._activity: dict[str, RepositoryActivity | None] = {}

    def info(self, dependency: Dependency) -> PackageInfo | None:
        key = dependency.key()

        if key not in self._info:
            self._info[key] = package_info(dependency.ecosystem, dependency.name, self.fetch)

        return self._info[key]

    def activity(self, slug: str) -> RepositoryActivity | None:
        if not slug or self.github_fetch is None:
            return None

        if slug not in self._activity:
            self._activity[slug] = repository_activity(slug, self.github_fetch)

        return self._activity[slug]

    def _resolve_range(self, dependency: Dependency) -> None:
        """
        Without a lockfile, a ranged dependency is checked as the newest
        release its range allows: what a fresh install would get.
        """

        if dependency.version or not dependency.spec:
            return

        info = self.info(dependency)

        if info is None:
            return

        version = newest_satisfying(dependency.ecosystem, dependency.spec, list(info.release_dates))

        if version:
            dependency.version = version
            dependency.resolved_from_range = True

    # ------------------------------------------------------------------

    def _collect_dependency_data(
        self,
        dependencies: list[Dependency],
        vulnerabilities: dict[int, list[Vulnerability]],
        remediations: dict[int, Any],
        project_category: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        advisories: list[dict[str, Any]] = []
        package_findings: set[tuple[str, str, str]] = set()
        for index, dependency in enumerate(dependencies):
            record, dependency_findings = self._collect_one_dependency(
                index,
                dependency,
                vulnerabilities,
                remediations,
                project_category,
                advisories,
            )
            records.append(record)
            findings.extend(dependency_findings[0])
            once = (
                dependency.ecosystem,
                normalize_package(dependency.ecosystem, dependency.name),
            )
            for finding in dependency_findings[1]:
                identity = (*once, finding["rule_id"])
                if identity not in package_findings:
                    package_findings.add(identity)
                    findings.append(finding)
        return records, findings, advisories

    def _collect_one_dependency(
        self,
        index: int,
        dependency: Dependency,
        vulnerabilities: dict[int, list[Vulnerability]],
        remediations: dict[int, Any],
        project_category: str,
        advisories: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
        info = self.info(dependency)
        reach = self.reachability.status(dependency)
        verdict = licensing.evaluate(info.license if info else "")
        freshness = _freshness(dependency, info)
        activity = self.activity(info.repository) if info else None
        package_url = purl(dependency.ecosystem, dependency.name, dependency.version)
        found = vulnerabilities.get(index, [])
        fix = remediations.get(index)
        record = {
            **dependency.to_dict(),
            "purl": package_url,
            "license": info.license if info else "",
            "license_spdx": verdict.options[0] if len(verdict.options) == 1 and verdict.category != licensing.UNKNOWN else "",
            "license_category": verdict.category if info else "",
            "reachability": reach,
            "registry": info.to_dict() if info else None,
            "upstream": activity.__dict__ if activity else None,
            "freshness": freshness,
            "vulnerabilities": [item.id for item in found],
            "remediation": fix.to_dict() if fix else None,
        }
        vulnerability_findings = self._vulnerability_findings(
            dependency, found, fix, reach, package_url, advisories
        )
        package_findings = list(
            self._package_findings(
                dependency, info, verdict, project_category, freshness, activity
            )
        )
        return record, (vulnerability_findings, package_findings)

    def run(self, repository: dict[str, Any] | None = None) -> dict[str, Any]:
        repository = dict(repository or {})
        repository.setdefault("name", self.root.resolve().name)
        repository["license"] = repository.get("license") or _project_license(self.root)

        project_category = licensing.evaluate(repository["license"]).category if repository["license"] else licensing.UNKNOWN

        dependencies = discover_dependencies(self.root)

        for dependency in dependencies:
            self._resolve_range(dependency)

        vulnerabilities, remediations = find_vulnerabilities(
            dependencies,
            post=self.post,
            fetch=self.fetch if self.post is not None else None,
        )

        records, findings, advisories = self._collect_dependency_data(
            dependencies, vulnerabilities, remediations, project_category
        )

        quality = analyse_quality(self.root)
        metrics = quality.metrics()
        quality_findings = [quality_finding(issue) for issue in quality.issues]

        findings.sort(key=lambda item: -int(item["risk"]["score"]))
        quality_findings.sort(key=lambda item: -int(item["risk"]["score"]))

        freshness_summary = self._freshness_summary(records)

        license_counts = self._license_counts(records)

        return {
            "schema": SCHEMA,
            "generated_at": self.today.isoformat(),
            "repository": repository,
            "statistics": {
                "dependencies": len(records),
                "direct": sum(1 for record in records if record["direct"]),
                "transitive": sum(1 for record in records if not record["direct"]),
                "vulnerable": sum(1 for record in records if record["vulnerabilities"]),
                "ecosystems": sorted({record["ecosystem"] for record in records}),
                "registry_lookups": self.fetch is not offline_fetcher,
                "advisory_lookups": self.post is not None,
            },
            "dependencies": records,
            "vulnerabilities": advisories,
            "licenses": {"project": repository["license"], "project_category": project_category, "categories": license_counts},
            "freshness": freshness_summary,
            "quality": {
                "metrics": metrics,
                "hotspots": quality.hotspots(),
                "findings": quality_findings,
            },
            "findings": findings,
            "summary": summarize(findings),
            "health": health_summary(findings, freshness_summary, metrics),
        }

    @staticmethod
    def _license_counts(records: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in records:
            category = record["license_category"]
            if category:
                counts[category] = counts.get(category, 0) + 1
        return counts

    # ------------------------------------------------------------------

    def _vulnerability_findings(self, dependency, found, fix, reach, package_url, advisories):
        results = []

        for vulnerability in found:
            advisory = {**vulnerability.to_dict(), "purl": package_url, "manifest": dependency.manifest, "line": dependency.line}
            advisories.append(advisory)

            confidence = FIRM

            if reach == NOT_IMPORTED or dependency.scope == DEVELOPMENT:
                confidence = TENTATIVE
            elif reach == IMPORTED:
                confidence = CONFIRMED

            if fix and fix.target:
                upgrade = f"Upgrade {dependency.name} from {dependency.version} to {fix.target}"

                if fix.breaking and fix.non_breaking_target:
                    upgrade += (
                        f" ({fix.target} is a major upgrade; {fix.non_breaking_target} stays on your "
                        "current major line but does not clear every advisory)"
                    )
                elif fix.breaking:
                    upgrade += f" ({fix.target} is a major upgrade: review its changelog for breaking changes)"
                else:
                    upgrade += ", a compatible upgrade that clears every known advisory"

                recommendation = upgrade + "."
            elif vulnerability.minimum_fix:
                recommendation = f"Upgrade {dependency.name} to at least {vulnerability.minimum_fix}."
            else:
                recommendation = (
                    f"No fixed release of {dependency.name} is published; replace the package or "
                    "mitigate the vulnerable feature."
                )

            reach_note = {
                IMPORTED: " First-party code imports this package.",
                NOT_IMPORTED: " No first-party code imports this package, so the vulnerable code is unlikely to be reachable.",
            }.get(reach, "")

            results.append(
                make_finding(
                    "REPO-DEP-001",
                    vulnerability.severity,
                    f"{dependency.name} {dependency.version} is affected by {vulnerability.id}"
                    f"{' (' + ', '.join(vulnerability.aliases[:2]) + ')' if vulnerability.aliases else ''}: "
                    f"{vulnerability.summary}{reach_note}",
                    recommendation,
                    _location(dependency),
                    {
                        "package": dependency.name,
                        "ecosystem": dependency.ecosystem,
                        "version": dependency.version,
                        "purl": package_url,
                        "advisory": vulnerability.id,
                        "aliases": vulnerability.aliases,
                        "cvss": vulnerability.cvss,
                        "fixed_in": vulnerability.fixed,
                        "minimum_fix": vulnerability.minimum_fix,
                        "upgrade_to": fix.target if fix else "",
                        "non_breaking_upgrade": fix.non_breaking_target if fix else "",
                        "breaking_upgrade": fix.breaking if fix else False,
                        "reachability": reach,
                        "scope": dependency.scope,
                        "direct": dependency.direct,
                        "manifest": dependency.manifest,
                        "line": dependency.line,
                    },
                    confidence=confidence,
                    title=f"{dependency.name} {dependency.version}: {vulnerability.id}",
                    references=[vulnerability.url, *vulnerability.references[:3]],
                )
            )

        return results

    def _lookalike_findings(
        self, dependency, location, evidence, age_days, downloads
    ):
        name = dependency.name
        squat = typosquat_target(dependency.ecosystem, name)
        if squat:
            suspicious_registry = (age_days is not None and age_days < NEW_PACKAGE_DAYS) or (
                downloads is not None and downloads < LOW_ADOPTION_DOWNLOADS
            )

            yield make_finding(
                "REPO-SUP-001",
                "critical" if suspicious_registry else "high",
                f"`{name}` differs from the popular package `{squat.target}` by {squat.technique}."
                + (f" It was first published {age_days} days ago." if age_days is not None else "")
                + (f" It has {downloads} downloads in the last week." if downloads is not None else ""),
                f"Confirm `{name}` is the package you intended. If you meant `{squat.target}`, replace it, "
                "rotate any credentials available to builds that installed it, and review the install scripts it ran.",
                location,
                {**evidence, "lookalike_of": squat.target, "technique": squat.technique, "age_days": age_days, "weekly_downloads": downloads},
                confidence=FIRM if suspicious_registry else TENTATIVE,
            )
        elif age_days is not None and age_days < NEW_PACKAGE_DAYS and downloads is not None and downloads < LOW_ADOPTION_DOWNLOADS:
            yield make_finding(
                "REPO-SUP-002",
                "low",
                f"`{name}` was first published {age_days} days ago and has {downloads} weekly downloads.",
                "Review the package source and maintainer before depending on it; prefer established alternatives.",
                location,
                {**evidence, "age_days": age_days, "weekly_downloads": downloads},
                confidence=TENTATIVE,
            )

    def _registry_status_findings(
        self, dependency, info, freshness, activity, location, evidence
    ):
        name = dependency.name
        runtime = dependency.scope != DEVELOPMENT
        if info.deprecated:
            yield make_finding(
                "REPO-DEP-002",
                "medium",
                f"{name} is deprecated: {info.deprecated}",
                f"Migrate away from {name} to its recommended successor.",
                location,
                {**evidence, "deprecation": info.deprecated},
                confidence=CONFIRMED,
            )

        if activity and activity.archived:
            yield make_finding(
                "REPO-DEP-004",
                "medium",
                f"The upstream repository of {name} ({info.repository}) is archived and read-only.",
                f"Plan a replacement for {name}; archived projects receive no security fixes.",
                location,
                {**evidence, "repository": info.repository},
                confidence=CONFIRMED,
            )

        self._emit_maintenance_findings(
            dependency, info, activity, location, evidence, runtime
        )
        behind = (freshness.get("behind") or {}).get("major", 0)
        if behind >= 2:
            yield make_finding(
                "REPO-DEP-005",
                "low",
                f"{name} {dependency.version} is {behind} major versions behind the latest {freshness['latest']}.",
                f"Plan an upgrade of {name} toward {freshness['latest']}; old major lines stop receiving fixes.",
                location,
                {**evidence, "latest": freshness["latest"], "major_versions_behind": behind, "libyears": freshness.get("libyears")},
                confidence=CONFIRMED,
            )

    def _emit_maintenance_findings(
        self, dependency, info, activity, location, evidence, runtime
    ):
        name = dependency.name
        idle_years = _years_between(info.latest_release, self.today)
        if not info.deprecated and idle_years is not None and idle_years >= UNMAINTAINED_YEARS:
            commits = activity.commits_last_year if activity else None
            if commits is None or commits < 5:
                yield make_finding(
                    "REPO-DEP-003",
                    "medium" if idle_years >= ABANDONED_YEARS else "low",
                    f"{name} has had no release for {idle_years:.1f} years"
                    + (f" and {commits} commits in the last year" if commits is not None else "")
                    + (f"; {activity.contributors} contributors" if activity and activity.contributors is not None else "")
                    + ".",
                    f"Check whether {name} is still maintained; budget for a fork or replacement if not.",
                    location,
                    {**evidence, "latest_release": info.latest_release, "idle_years": round(idle_years, 1),
                     "commits_last_year": commits, "contributors": activity.contributors if activity else None},
                )

        if info.maintainers == 1 and runtime:
            yield make_finding(
                "REPO-DEP-007",
                "informational",
                f"{name} is published by a single maintainer account.",
                "Single-maintainer packages are a bus-factor and account-takeover risk; monitor releases closely.",
                location,
                {**evidence, "maintainers": 1},
                confidence=CONFIRMED,
            )

    def _package_findings(self, dependency, info, verdict, project_category, freshness, activity):
        name = dependency.name
        location = _location(dependency)
        evidence = {"package": name, "ecosystem": dependency.ecosystem, "version": dependency.version, "scope": dependency.scope}
        runtime = dependency.scope != DEVELOPMENT
        age_days = None
        if info and info.first_release:
            first = parse_time(info.first_release)
            age_days = (self.today - first).days if first else None
        downloads = info.weekly_downloads if info else None
        yield from self._lookalike_findings(
            dependency, location, evidence, age_days, downloads
        )
        if info is None:
            if dependency.direct and not dependency.version and dependency.spec and runtime:
                yield self._unpinned(dependency, location, evidence)
            return
        yield from self._registry_status_findings(
            dependency, info, freshness, activity, location, evidence
        )

        if dependency.direct and (dependency.resolved_from_range or not dependency.version) and dependency.spec and runtime:
            yield self._unpinned(dependency, location, evidence)

        if runtime:
            yield from self._license_findings(dependency, info, verdict, project_category, location, evidence)

    def _unpinned(self, dependency, location, evidence):
        return make_finding(
            "REPO-DEP-006",
            "informational",
            f"{dependency.name} is declared as `{dependency.spec}` and no lockfile resolves it, so builds may install different releases"
            + (f" (currently {dependency.version})." if dependency.version else "."),
            "Commit a lockfile (or pin exact versions) so builds are reproducible and advisories can be matched.",
            location,
            {**evidence, "spec": dependency.spec},
            confidence=CONFIRMED,
        )

    def _license_findings(self, dependency, info, verdict, project_category, location, evidence):
        name = dependency.name
        detail = {**evidence, "license": info.license, "category": verdict.category, "project_category": project_category}

        if verdict.dual_license_trap:
            yield make_finding(
                "REPO-LIC-005",
                "medium",
                f"{name} is offered as `{info.license}`: the only free option is copyleft, so proprietary use needs a paid licence.",
                f"Obtain a commercial licence for {name} or replace it.",
                location,
                detail,
            )
            return

        if not licensing.conflicts_with_project(verdict.category, project_category):
            return

        rule, severity, text = {
            licensing.STRONG_COPYLEFT: ("REPO-LIC-001", "high", "requires derivative works to be released under the same licence"),
            licensing.NETWORK_COPYLEFT: ("REPO-LIC-002", "high", "requires source disclosure even when the software is only offered over a network"),
            licensing.NON_COMMERCIAL: ("REPO-LIC-003", "high", "restricts commercial use or is proprietary"),
            licensing.UNKNOWN: ("REPO-LIC-004", "low", "could not be identified, so its obligations are unknown"),
            licensing.WEAK_COPYLEFT: ("REPO-LIC-006", "low", "requires modifications to the library itself to be shared"),
        }[verdict.category]

        yield make_finding(
            rule,
            severity,
            f"{name} is licensed `{info.license or 'unspecified'}`, which {text}.",
            f"Have legal review {name}'s licence against how you distribute the product, or replace it with a permissively licensed alternative.",
            location,
            detail,
        )

    @staticmethod
    def _freshness_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
        known = [record["freshness"] for record in records if record["freshness"]]

        current = sum(1 for item in known if item["behind"]["major"] == 0 and item["behind"]["minor"] == 0)

        return {
            "known": len(known),
            "up_to_date": sum(1 for item in known if item["up_to_date"]),
            "outdated": sum(1 for item in known if not item["up_to_date"]),
            "major_behind": sum(1 for item in known if item["behind"]["major"] > 0),
            "minor_behind": sum(1 for item in known if item["behind"]["major"] == 0 and item["behind"]["minor"] > 0),
            "libyears": round(sum(item.get("libyears") or 0 for item in known), 2),
            "freshness_index": round(100 * current / len(known)) if known else None,
        }


def scan_repository(root: Path, repository: dict[str, Any] | None = None, **options: Any) -> dict[str, Any]:
    return RepositoryScanner(root, **options).run(repository)
