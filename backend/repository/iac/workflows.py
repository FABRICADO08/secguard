"""GitHub Actions checks: token permissions, untrusted PR checkouts, script injection, unpinned actions."""

from __future__ import annotations

import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

_TOP_PERMISSIONS = re.compile(r"^permissions\s*:")
_PERMISSIONS = re.compile(r"^\s+permissions\s*:")
_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\b")
_HEAD_CHECKOUT = re.compile(
    r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|head_ref)\s*\}\}"
    r"|refs/pull/\$\{\{\s*github\.event\.(?:pull_request\.)?number\s*\}\}/(?:merge|head)"
    r"|\bgh\s+pr\s+checkout\b"
)
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


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _jobs_body(lines: list[str]) -> list[tuple[int, str]]:
    """Non-blank, non-comment (index, line) pairs nested under the top-level `jobs:` key."""
    start = next((index for index, line in enumerate(lines) if re.match(r"^jobs\s*:\s*(?:#.*)?$", line)), len(lines))
    body = []
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.lstrip().startswith("#"):
            if _indent(line) == 0:
                break
            body.append((index, line))
    return body


def _jobs(lines: list[str]) -> list[tuple[int, list[str]]]:
    """(line number, block lines) for each job under the top-level `jobs:` key."""
    body = _jobs_body(lines)
    depth = _indent(body[0][1]) if body else 0
    headers = [position for position, (_, line) in enumerate(body) if _indent(line) == depth]
    return [(body[first][0] + 1, [line for _, line in body[first:last]])
            for first, last in zip(headers, [*headers[1:], len(body)])]


def _write_all(path: str, lines: list[str]) -> list[SecurityIssue]:
    return [
        SecurityIssue("REPO-IAC-012", path, number,
                      "`permissions: write-all` gives every step a token that can write to the repository.", snippet(line))
        for number, line in enumerate(lines, start=1)
        if _WRITE_ALL.match(line) and not suppressed(line)
    ][:1]


def _unrestricted_jobs(path: str, lines: list[str]) -> list[SecurityIssue]:
    jobs = _jobs(lines)
    if not jobs:
        return [SecurityIssue("REPO-IAC-012", path, 1,
                              "The workflow sets no `permissions`, so its token gets the repository's default (often write) access.")]
    return [
        SecurityIssue("REPO-IAC-012", path, number,
                      f"Job `{block[0].strip().rstrip(':')}` sets no `permissions` and the workflow has no top-level default, "
                      "so its token gets the repository's default (often write) access.", snippet(block[0]))
        for number, block in jobs
        if not suppressed(block[0]) and not any(_PERMISSIONS.match(line) for line in block[1:])
    ]


def _permission_issues(path: str, lines: list[str]) -> list[SecurityIssue]:
    write_all = _write_all(path, lines)
    if write_all or any(_TOP_PERMISSIONS.match(line) for line in lines):
        return write_all
    return _unrestricted_jobs(path, lines)


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
