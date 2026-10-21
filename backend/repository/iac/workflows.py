"""GitHub Actions checks: token permissions, untrusted PR checkouts, script injection, unpinned actions."""

from __future__ import annotations

import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

_PERMISSIONS = re.compile(r"^\s*permissions\s*:")
_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\b")
_HEAD_CHECKOUT = re.compile(r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}")
_UNTRUSTED = re.compile(
    r"\$\{\{\s*(github\.head_ref|github\.event\.(?!repository\.|inputs\.|sender\.)[\w.*\[\]-]*\."
    r"(?:title|body|message|label|name|email|ref|head_ref|default_branch|page_name))\s*\}\}"
)
_USES = re.compile(r"^\s*-?\s*uses\s*:\s*[\"']?([^\s\"'#@]+)@([^\s\"'#]+)")
_TRUSTED_OWNERS = ("actions/", "github/")


def _run_lines(lines: list[str]) -> list[int]:
    """Indexes of lines that are part of a `run:` script."""
    result, indent = [], None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        current = len(line) - len(stripped)
        if indent is not None and stripped and current > indent:
            result.append(index)
            continue
        indent = None
        run = re.match(r"^(\s*)-?\s*run\s*:\s*(.*)$", line)
        if run:
            result.append(index)
            indent = current if run.group(2).strip() in ("|", ">", "|-", ">-", "") else None
    return result


def _permission_issues(path: str, lines: list[str]) -> list[SecurityIssue]:
    for number, line in enumerate(lines, start=1):
        if _WRITE_ALL.match(line) and not suppressed(line):
            return [SecurityIssue("REPO-IAC-012", path, number,
                                  "`permissions: write-all` gives every step a token that can write to the repository.", snippet(line))]
    if any(_PERMISSIONS.match(line) for line in lines):
        return []
    return [SecurityIssue("REPO-IAC-012", path, 1,
                          "The workflow sets no `permissions`, so its token gets the repository's default (often write) access.")]


def _checkout_issues(path: str, text: str, lines: list[str]) -> list[SecurityIssue]:
    if "pull_request_target" not in text:
        return []
    return [
        SecurityIssue("REPO-IAC-013", path, number,
                      "A `pull_request_target` workflow checks out the pull request's code, which then runs with repository secrets.",
                      snippet(line))
        for number, line in enumerate(lines, start=1)
        if _HEAD_CHECKOUT.search(line) and not suppressed(line)
    ]


def _injection_issues(path: str, lines: list[str]) -> list[SecurityIssue]:
    issues = []
    for index in _run_lines(lines):
        match = _UNTRUSTED.search(lines[index])
        if match and not suppressed(lines[index]):
            issues.append(SecurityIssue(
                "REPO-IAC-014", path, index + 1,
                f"`{match.group(1)}` is controlled by whoever opens the issue or pull request and is pasted into a shell script.",
                snippet(lines[index])))
    return issues


def _pinning_issues(path: str, lines: list[str]) -> list[SecurityIssue]:
    issues = []
    for number, line in enumerate(lines, start=1):
        uses = _USES.match(line)
        if not uses or suppressed(line):
            continue
        action, ref = uses.groups()
        if action.startswith(("./", "docker://", *_TRUSTED_OWNERS)) or re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        issues.append(SecurityIssue("REPO-IAC-015", path, number,
                                    f"Third-party action `{action}` is referenced by the movable ref `{ref}` instead of a commit SHA.",
                                    snippet(line)))
    return issues


def workflow_issues(path: str, text: str) -> list[SecurityIssue]:
    lines = text.splitlines()
    issues = (_permission_issues(path, lines) + _checkout_issues(path, text, lines)
              + _injection_issues(path, lines) + _pinning_issues(path, lines))
    return sorted(issues, key=lambda issue: issue.line)
