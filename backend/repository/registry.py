"""
Package-registry metadata: latest release, release dates, licence,
deprecation, maintainers and adoption.

Every lookup goes through a `Fetcher`, so the scanner can run offline
and tests can substitute recorded responses.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

from backend.repository.versions import (
    GO,
    NPM,
    PYPI,
    RUBYGEMS,
    compare,
    is_prerelease,
)

Fetcher = Callable[[str], Any]

TIMEOUT = 10

USER_AGENT = "SecGuard-repository-scanner/1.0"


class HttpFetcher:
    """GET a JSON document, returning None on any failure. Cached."""

    def __init__(self, headers: dict[str, str] | None = None) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, **(headers or {})})
        self.cache: dict[str, Any] = {}

    def __call__(self, url: str) -> Any:
        if url in self.cache:
            return self.cache[url]

        try:
            response = self.session.get(url, timeout=TIMEOUT)
            data = response.json() if response.status_code == 200 else None
        except (requests.RequestException, ValueError):
            data = None

        self.cache[url] = data

        return data


def offline_fetcher(_url: str) -> Any:
    return None


@dataclass
class PackageInfo:
    latest: str = ""
    license: str = ""
    deprecated: str = ""
    maintainers: int | None = None
    weekly_downloads: int | None = None
    first_release: str = ""
    latest_release: str = ""
    release_dates: dict[str, str] = field(default_factory=dict)
    repository: str = ""

    def released(self, version: str) -> str:
        return self.release_dates.get(version, "")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("release_dates")
        return data


def parse_time(value: str) -> datetime | None:
    if not value:
        return None

    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _github_repository(url: str) -> str:
    match = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)", url or "")

    return f"{match.group(1)}/{match.group(2)}" if match else ""


def _stable_latest(ecosystem: str, versions: list[str], fallback: str) -> str:
    stable = [version for version in versions if not is_prerelease(ecosystem, version)]

    if not stable:
        return fallback

    best = stable[0]

    for version in stable[1:]:
        if compare(ecosystem, version, best) > 0:
            best = version

    return best


def _pypi_release_dates(document: dict[str, Any]) -> dict[str, str]:
    dates: dict[str, str] = {}
    for version, files in (document.get("releases") or {}).items():
        uploads = sorted(
            str(item.get("upload_time_iso_8601") or "")
            for item in files or []
            if not item.get("yanked")
        )

        if uploads and uploads[0]:
            dates[version] = uploads[0]
    return dates


def _pypi_license(info: dict[str, Any], classifiers: list[str]) -> str:
    license_text = str(info.get("license_expression") or "")
    if not license_text:
        declared = str(info.get("license") or "").strip()
        license_text = declared if 0 < len(declared) <= 80 else ""
    if not license_text:
        return " OR ".join(
            item.rsplit("::", 1)[-1].strip()
            for item in classifiers
            if item.startswith("License ::") and "OSI Approved ::" in item
        )
    return license_text


def _pypi_repository(info: dict[str, Any]) -> str:
    urls = info.get("project_urls") or {}
    return next(
        (
            _github_repository(str(url))
            for url in [*urls.values(), info.get("home_page") or ""]
            if _github_repository(str(url))
        ),
        "",
    )


def _pypi(name: str, fetch: Fetcher) -> PackageInfo | None:
    document = fetch(f"https://pypi.org/pypi/{quote(name)}/json")
    if not isinstance(document, dict):
        return None

    info = document.get("info") or {}
    dates = _pypi_release_dates(document)
    classifiers = info.get("classifiers") or []
    downloads = fetch(f"https://pypistats.org/api/packages/{quote(name.lower())}/recent")
    weekly = None
    if isinstance(downloads, dict):
        weekly = (downloads.get("data") or {}).get("last_week")

    ordered = sorted(dates.values())
    latest = _stable_latest(PYPI, list(dates), str(info.get("version") or ""))

    return PackageInfo(
        latest=latest,
        license=_pypi_license(info, classifiers),
        deprecated=(
            "Marked inactive on PyPI"
            if "Development Status :: 7 - Inactive" in classifiers
            else ""
        ),
        maintainers=None,
        weekly_downloads=weekly if isinstance(weekly, int) else None,
        first_release=ordered[0] if ordered else "",
        latest_release=ordered[-1] if ordered else "",
        release_dates=dates,
        repository=_pypi_repository(info),
    )


def _npm(name: str, fetch: Fetcher) -> PackageInfo | None:
    encoded = quote(name, safe="@")
    encoded = encoded.replace("/", "%2F")

    document = fetch(f"https://registry.npmjs.org/{encoded}")

    if not isinstance(document, dict) or "versions" not in document:
        return None

    times = {
        key: str(value)
        for key, value in (document.get("time") or {}).items()
        if key not in {"created", "modified"}
    }

    latest = str((document.get("dist-tags") or {}).get("latest") or "")

    manifest = (document.get("versions") or {}).get(latest) or {}

    license_value = manifest.get("license") or document.get("license") or ""

    if isinstance(license_value, dict):
        license_value = license_value.get("type") or ""

    downloads = fetch(f"https://api.npmjs.org/downloads/point/last-week/{name}")

    repository = document.get("repository") or {}

    ordered = sorted(times.values())

    return PackageInfo(
        latest=latest,
        license=str(license_value),
        deprecated=str(manifest.get("deprecated") or ""),
        maintainers=len(document.get("maintainers") or []) or None,
        weekly_downloads=(downloads or {}).get("downloads") if isinstance(downloads, dict) else None,
        first_release=str((document.get("time") or {}).get("created") or (ordered[0] if ordered else "")),
        latest_release=times.get(latest, ordered[-1] if ordered else ""),
        release_dates=times,
        repository=_github_repository(
            str(repository.get("url") if isinstance(repository, dict) else repository)
        ),
    )


def _go(name: str, fetch: Fetcher) -> PackageInfo | None:
    escaped = re.sub(r"[A-Z]", lambda match: "!" + match.group(0).lower(), name)

    document = fetch(f"https://proxy.golang.org/{escaped}/@latest")

    if not isinstance(document, dict):
        return None

    return PackageInfo(
        latest=str(document.get("Version") or ""),
        latest_release=str(document.get("Time") or ""),
        repository=_github_repository("https://" + name),
    )


def _rubygems(name: str, fetch: Fetcher) -> PackageInfo | None:
    document = fetch(f"https://rubygems.org/api/v1/gems/{quote(name)}.json")

    if not isinstance(document, dict):
        return None

    return PackageInfo(
        latest=str(document.get("version") or ""),
        license=" OR ".join(document.get("licenses") or []),
        latest_release=str(document.get("version_created_at") or ""),
        weekly_downloads=None,
        repository=_github_repository(str(document.get("source_code_uri") or "")),
    )


LOOKUPS = {PYPI: _pypi, NPM: _npm, GO: _go, RUBYGEMS: _rubygems}


def package_info(ecosystem: str, name: str, fetch: Fetcher) -> PackageInfo | None:
    lookup = LOOKUPS.get(ecosystem)

    return lookup(name, fetch) if lookup else None


@dataclass
class RepositoryActivity:
    archived: bool = False
    pushed_at: str = ""
    commits_last_year: int | None = None
    contributors: int | None = None


def repository_activity(slug: str, fetch: Fetcher) -> RepositoryActivity | None:
    """Upstream activity from the GitHub API; needs a token to be useful at scale."""

    if not slug:
        return None

    document = fetch(f"https://api.github.com/repos/{slug}")

    if not isinstance(document, dict) or "archived" not in document:
        return None

    since = datetime.now(timezone.utc).replace(microsecond=0)
    since = since.replace(year=since.year - 1).isoformat().replace("+00:00", "Z")

    commits = fetch(f"https://api.github.com/repos/{slug}/commits?since={since}&per_page=100")

    contributors = fetch(f"https://api.github.com/repos/{slug}/contributors?per_page=100")

    return RepositoryActivity(
        archived=bool(document.get("archived")),
        pushed_at=str(document.get("pushed_at") or ""),
        commits_last_year=len(commits) if isinstance(commits, list) else None,
        contributors=len(contributors) if isinstance(contributors, list) else None,
    )
