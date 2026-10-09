"""
Pull-request review: inline comments on the lines a pull request
touches, with GitHub ``suggestion`` blocks for dependency upgrades so a
reviewer can apply the fix with one click.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from backend.repository.sarif import split_location

API = "https://api.github.com"

MAX_COMMENTS = 30

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def commentable_lines(patch: str) -> set[int]:
    """New-file line numbers GitHub accepts review comments on."""

    lines: set[int] = set()
    current = 0

    for raw in (patch or "").splitlines():
        match = _HUNK.match(raw)

        if match:
            current = int(match.group(1))
            continue

        if raw.startswith("-"):
            continue

        if raw.startswith(("+", " ")):
            lines.add(current)
            current += 1

    return lines


def suggested_line(line: str, current: str, target: str) -> str | None:
    """The manifest line with ``current`` replaced by ``target``, if found."""

    pattern = re.compile(rf"(?<![\w.]){re.escape(current)}(?![\w.])")

    if not pattern.search(line):
        return None

    return pattern.sub(target, line, count=1)


@dataclass
class ReviewComment:
    path: str
    line: int
    body: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "side": "RIGHT", "body": self.body}


def _upgrade_target(evidence: dict[str, Any]) -> str:
    if evidence.get("upgrade_to") and not evidence.get("breaking_upgrade"):
        return str(evidence["upgrade_to"])

    return str(evidence.get("non_breaking_upgrade") or evidence.get("upgrade_to") or "")


def _upgrade_comments(
    report: dict[str, Any],
    changed: dict[str, set[int]],
    root: Path,
) -> list[ReviewComment]:
    comments = []
    upgrades: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for finding in report.get("findings") or []:
        if finding.get("rule_id") == "REPO-DEP-001":
            path, line = split_location(finding.get("location", ""))
            if path and line:
                upgrades.setdefault((path, line), []).append(finding)
    for (path, line), group in sorted(upgrades.items()):
        if line not in changed.get(path, set()):
            continue
        evidence = group[0].get("evidence") or {}
        target = _upgrade_target(evidence)
        advisories = ", ".join(sorted({str((item.get("evidence") or {}).get("advisory")) for item in group}))
        worst = max(group, key=lambda item: SEVERITY_RANK.get(item.get("severity"), 0))["severity"]
        body = f"**SecGuard: {evidence.get('package')} {evidence.get('version')} has {len(group)} known {worst}-or-lower vulnerabilit{'y' if len(group) == 1 else 'ies'}** ({advisories})."
        source = root / path
        text_lines = source.read_text(encoding="utf-8", errors="replace").splitlines() if source.is_file() else []
        if target and 0 < line <= len(text_lines):
            replacement = suggested_line(text_lines[line - 1], str(evidence.get("version")), target)
            if replacement is not None:
                note = " This crosses a major version; review the changelog." if evidence.get("breaking_upgrade") and target == evidence.get("upgrade_to") else ""
                body += f"\n\nUpgrade to `{target}`:{note}\n\n```suggestion\n{replacement}\n```"
        comments.append(ReviewComment(path, line, body))
    return comments


def _finding_comments(
    report: dict[str, Any],
    changed: dict[str, set[int]],
    threshold: int,
) -> list[ReviewComment]:
    comments = []
    quality = (report.get("quality") or {}).get("findings") or []
    for finding in [*quality, *[item for item in report.get("findings") or [] if item.get("rule_id") != "REPO-DEP-001"]]:
        if SEVERITY_RANK.get(finding.get("severity"), 0) < threshold:
            continue
        path, line = split_location(finding.get("location", ""))
        if line and line in changed.get(path, set()):
            comments.append(
                ReviewComment(
                    path,
                    line,
                    f"**SecGuard {finding['rule_id']} ({finding['severity']}): {finding['title']}**\n\n"
                    f"{finding.get('description', '')}\n\n{finding.get('recommendation', '')}",
                )
            )
    return comments


def _review_body(report: dict[str, Any], comments: list[ReviewComment]) -> str:
    health = report.get("health") or {}
    overall = health.get("overall") or {}
    summary = report.get("summary") or {}
    counts = summary.get("severity_counts") or {}

    body = (
        f"### SecGuard health: {overall.get('grade', '?')} ({overall.get('score', '?')}/100)\n\n"
        f"| Security | Open source | Maintainability |\n|---|---|---|\n"
        f"| {(health.get('security') or {}).get('grade', '?')} | {(health.get('open_source') or {}).get('grade', '?')} "
        f"| {(health.get('maintainability') or {}).get('grade', '?')} |\n\n"
        f"Findings: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low."
    )

    if len(comments) > MAX_COMMENTS:
        body += f"\n\nShowing {MAX_COMMENTS} of {len(comments)} inline comments; see the code scanning alerts for the rest."

    return body


def build_review(
    report: dict[str, Any],
    changed: dict[str, set[int]],
    root: Path,
    minimum_severity: str = "low",
) -> tuple[list[ReviewComment], str]:
    threshold = SEVERITY_RANK.get(minimum_severity, 1)
    comments = _upgrade_comments(report, changed, root)
    comments.extend(_finding_comments(report, changed, threshold))
    body = _review_body(report, comments)
    return comments[:MAX_COMMENTS], body


class GitHubClient:
    def __init__(self, token: str, request: Callable[..., Any] | None = None) -> None:
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.request = request or requests.request

    def changed_lines(self, repository: str, number: int) -> dict[str, set[int]]:
        changed: dict[str, set[int]] = {}
        page = 1

        while True:
            response = self.request(
                "GET",
                f"{API}/repos/{repository}/pulls/{number}/files",
                headers=self.headers,
                params={"per_page": 100, "page": page},
                timeout=30,
            )
            response.raise_for_status()
            files = response.json()

            for item in files:
                changed[item["filename"]] = commentable_lines(item.get("patch", ""))

            if len(files) < 100:
                return changed

            page += 1

    def post_review(self, repository: str, number: int, commit: str, body: str, comments: list[ReviewComment]) -> Any:
        response = self.request(
            "POST",
            f"{API}/repos/{repository}/pulls/{number}/reviews",
            headers=self.headers,
            json={
                "commit_id": commit,
                "body": body,
                "event": "COMMENT",
                "comments": [comment.to_dict() for comment in comments],
            },
            timeout=30,
        )
        response.raise_for_status()

        return response.json()
