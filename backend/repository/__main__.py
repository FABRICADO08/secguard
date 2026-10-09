"""
Command line entry point, used by the SecGuard GitHub Action:

    python -m backend.repository scan . --output report.json --sarif secguard.sarif
    python -m backend.repository review --report report.json --pull 12
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests

from backend.repository.registry import HttpFetcher, offline_fetcher
from backend.repository.sarif import to_sarif
from backend.repository.sbom import cyclonedx, spdx
from backend.repository.scanner import scan_repository
from backend.repository.suggestions import SEVERITY_RANK, GitHubClient, build_review
from backend.repository.vulnerabilities import http_poster
from backend.storage import application_names


def _write(path: str, document: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(document, indent=2), encoding="utf-8")


def _oidc_token(audience: str) -> str:
    """A GitHub Actions OIDC token, proving which repository is uploading."""

    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

    if not url or not token:
        return ""

    response = requests.get(
        url,
        params={"audience": audience},
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    response.raise_for_status()

    return str(response.json().get("value") or "")


def upload(report: dict[str, Any], server: str, api_token: str) -> dict[str, Any]:
    server = server.rstrip("/")
    bearer = api_token or _oidc_token(server)

    if not bearer:
        raise SystemExit("No SECGUARD_API_TOKEN and no GitHub OIDC token available for upload.")

    response = requests.post(
        f"{server}/api/repository/scans",
        json=report,
        headers={"Authorization": f"Bearer {bearer}"},
        timeout=120,
    )

    if response.status_code >= 400:
        raise SystemExit(f"Upload failed with HTTP {response.status_code}: {response.text[:500]}")

    return response.json()


def _repository_metadata(arguments: argparse.Namespace, root: Path) -> dict[str, Any]:
    return {
        "name": arguments.name or os.environ.get("GITHUB_REPOSITORY") or root.name,
        "commit": arguments.commit or os.environ.get("GITHUB_SHA", ""),
        "ref": arguments.ref or os.environ.get("GITHUB_REF", ""),
        "provider": "github" if os.environ.get("GITHUB_ACTIONS") or arguments.name else "local",
        "trigger": os.environ.get("GITHUB_EVENT_NAME", "manual"),
    }


def _set_application_name(arguments: argparse.Namespace, repository: dict[str, Any]) -> None:
    name = arguments.application_name or os.environ.get("SECGUARD_APPLICATION_NAME", "")
    if not name.strip():
        return

    problem = application_names.name_problem(name)
    if problem:
        raise SystemExit(f"--application-name: {problem}")

    repository["application_name"] = application_names.normalise(name)


def _write_scan_outputs(arguments: argparse.Namespace, report: dict[str, Any]) -> None:
    if arguments.output:
        _write(arguments.output, report)
    if arguments.sarif:
        _write(arguments.sarif, to_sarif(report))
    if arguments.cyclonedx:
        _write(arguments.cyclonedx, cyclonedx(report))
    if arguments.spdx:
        _write(arguments.spdx, spdx(report))


def _report_failure(report: dict[str, Any], fail_on: str) -> int:
    if fail_on == "none":
        return 0

    threshold = SEVERITY_RANK[fail_on]
    if any(
        SEVERITY_RANK.get(finding["severity"], 0) >= threshold
        for finding in report["findings"]
    ):
        print(f"Failing: findings at or above '{fail_on}'.", file=sys.stderr)
        return 1
    return 0


def command_scan(arguments: argparse.Namespace) -> int:
    root = Path(arguments.path).resolve()

    github_token = os.environ.get(arguments.github_token_env, "") if arguments.github_token_env else ""

    options: dict[str, Any] = {}

    if not arguments.offline:
        options["fetch"] = HttpFetcher()
        options["post"] = http_poster

        if github_token:
            options["github_fetch"] = HttpFetcher({"Authorization": f"Bearer {github_token}"})
    else:
        options["fetch"] = offline_fetcher

<<<<<<< HEAD
    repository = _repository_metadata(arguments, root)
    _set_application_name(arguments, repository)
=======
    report = scan_repository(root, _repository_metadata(arguments, root), **options)
    _write_scan_outputs(arguments, report)

    health = report["health"]["overall"]
    counts = report["summary"]["severity_counts"]

    _print_scan_summary(report, health, counts)

    if arguments.upload:
        result = upload(report, arguments.upload, os.environ.get("SECGUARD_API_TOKEN", ""))
        print(f"Uploaded as application {result.get('application_id')}.")

    if _should_fail(report, arguments.fail_on):
        print(f"Failing: findings at or above '{arguments.fail_on}'.", file=sys.stderr)
        return 1

    return 0


def _repository_metadata(
    arguments: argparse.Namespace,
    root: Path,
) -> dict[str, str]:
    repository = {
        "name": arguments.name or os.environ.get("GITHUB_REPOSITORY") or root.name,
        "commit": arguments.commit or os.environ.get("GITHUB_SHA", ""),
        "ref": arguments.ref or os.environ.get("GITHUB_REF", ""),
        "provider": "github" if os.environ.get("GITHUB_ACTIONS") or arguments.name else "local",
        "trigger": os.environ.get("GITHUB_EVENT_NAME", "manual"),
    }
    application_name = (
        arguments.application_name
        or os.environ.get("SECGUARD_APPLICATION_NAME", "")
    )
    if application_name.strip():
        problem = application_names.name_problem(application_name)
        if problem:
            raise SystemExit(f"--application-name: {problem}")
        repository["application_name"] = application_names.normalise(application_name)
>>>>>>> origin/main

    server_url = os.environ.get("GITHUB_SERVER_URL")
    repository_name = os.environ.get("GITHUB_REPOSITORY")
    if server_url and repository_name:
        repository["url"] = f"{server_url}/{repository_name}"
    return repository


<<<<<<< HEAD
    _write_scan_outputs(arguments, report)

    health = report["health"]["overall"]
    counts = report["summary"]["severity_counts"]
=======
def _write_scan_outputs(
    arguments: argparse.Namespace,
    report: dict[str, Any],
) -> None:
    outputs = (
        (arguments.output, report),
        (arguments.sarif, to_sarif(report) if arguments.sarif else None),
        (arguments.cyclonedx, cyclonedx(report) if arguments.cyclonedx else None),
        (arguments.spdx, spdx(report) if arguments.spdx else None),
    )
    for path, document in outputs:
        if path:
            _write(path, document)

>>>>>>> origin/main

def _print_scan_summary(
    report: dict[str, Any],
    health: dict[str, Any],
    counts: dict[str, int],
) -> None:
    print(
        f"SecGuard: health {health['grade']} ({health['score']}/100), "
        f"{report['statistics']['dependencies']} dependencies, "
        f"{counts['critical']} critical / {counts['high']} high / {counts['medium']} medium findings, "
        f"{len(report['quality']['findings'])} maintainability findings."
    )


<<<<<<< HEAD
    return _report_failure(report, arguments.fail_on)
=======
def _should_fail(report: dict[str, Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(
        SEVERITY_RANK.get(finding["severity"], 0) >= threshold
        for finding in report["findings"]
    )
>>>>>>> origin/main


def command_review(arguments: argparse.Namespace) -> int:
    token = os.environ.get(arguments.token_env, "")
    repository = arguments.repository or os.environ.get("GITHUB_REPOSITORY", "")
    number, commit = _review_coordinates(arguments)

    if not (token and repository and number and commit):
        print("Not a pull request run (or no token); skipping review.")
        return 0

    report = json.loads(Path(arguments.report).read_text(encoding="utf-8"))

    client = GitHubClient(token)

    try:
        changed = client.changed_lines(repository, int(number))
        comments, body = build_review(report, changed, Path(arguments.root), arguments.min_severity)
        client.post_review(repository, int(number), commit, body, comments)
    except requests.HTTPError as exc:
        # Pull requests from forks get a read-only token.
        print(f"Could not post the review: {exc}", file=sys.stderr)
        return 0

    print(f"Posted a review with {len(comments)} inline comments.")

    return 0


def _review_coordinates(
    arguments: argparse.Namespace,
) -> tuple[Any, str]:
    number = arguments.pull
    commit = arguments.commit
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if event_path and Path(event_path).is_file() and (not number or not commit):
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pull = event.get("pull_request") or {}
        number = number or pull.get("number")
        commit = commit or (pull.get("head") or {}).get("sha", "")
    return number, commit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.repository")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Scan a checked-out repository.")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--name", default="", help="owner/repo; defaults to $GITHUB_REPOSITORY.")
    scan.add_argument("--application-name", default="", help="Name shown in SecGuard; defaults to $SECGUARD_APPLICATION_NAME, then the repository name.")
    scan.add_argument("--commit", default="")
    scan.add_argument("--ref", default="")
    scan.add_argument("--output", default="secguard-report.json")
    scan.add_argument("--sarif", default="")
    scan.add_argument("--cyclonedx", default="")
    scan.add_argument("--spdx", default="")
    scan.add_argument("--offline", action="store_true", help="No registry or advisory lookups.")
    scan.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Env var with a token for upstream repository activity.")
    scan.add_argument("--upload", default="", help="SecGuard server URL to upload the report to.")
    scan.add_argument("--fail-on", default="none", choices=["none", *SEVERITY_RANK])
    scan.set_defaults(handler=command_scan)

    review = commands.add_parser("review", help="Post inline pull-request review comments.")
    review.add_argument("--report", default="secguard-report.json")
    review.add_argument("--root", default=".")
    review.add_argument("--repository", default="")
    review.add_argument("--pull", type=int, default=0)
    review.add_argument("--commit", default="")
    review.add_argument("--token-env", default="GITHUB_TOKEN")
    review.add_argument("--min-severity", default="low", choices=list(SEVERITY_RANK))
    review.set_defaults(handler=command_review)

    arguments = parser.parse_args(argv)

    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
