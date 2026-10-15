"""Hard-coded secrets in the working tree and in git history."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs the local git binary with fixed arguments
import threading
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from backend.repository.code_issues import SecurityIssue, is_test_path, suppressed
from backend.rules.generic.clientside import SECRET_PATTERNS, is_placeholder

CONFIG_SUFFIXES = frozenset(
    {".env", ".yml", ".yaml", ".json", ".properties", ".xml", ".config", ".ini", ".toml", ".cfg", ".conf", ".sh", ".tf", ".tfvars", ".ps1"}
)
SKIPPED_SUFFIXES = (".lock", "-lock.json", ".min.js", ".map", ".svg")
HISTORY_COMMITS = 1000
HISTORY_SECONDS = 120


def scans_for_secrets(path: str, source_suffixes: set[str] | frozenset[str]) -> bool:
    name = PurePosixPath(path).name.lower()
    if is_test_path(path) or name.endswith(SKIPPED_SUFFIXES):
        return False
    suffix = PurePosixPath(name).suffix
    return suffix in source_suffixes or suffix in CONFIG_SUFFIXES or name.startswith(".env")


def mask(value: str) -> str:
    return f"{value[:4]}…({len(value)} chars)"


def line_secrets(line: str) -> list[tuple[str, str]]:
    if suppressed(line):
        return []
    found = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            if not is_placeholder(match.group(0)):
                found.append((label, match.group(0)))
    return found


def tree_secrets(path: str, text: str) -> tuple[list[SecurityIssue], set[str]]:
    issues: list[SecurityIssue] = []
    values: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        for label, value in line_secrets(line):
            values.add(value)
            issues.append(
                SecurityIssue("REPO-SEC-005", path, number, f"{label} is written into the source.",
                              details={"kind": label, "secret": mask(value)})
            )
    return issues, values


def _git_log(root: Path) -> subprocess.Popen[str] | None:
    git = shutil.which("git")
    if git is None:
        return None
    return subprocess.Popen(  # nosec B603 - fixed argument list, no shell
        [git, "-C", str(root), "log", "-p", "--relative", "--no-color", "--no-ext-diff", "--unified=0",
         f"--max-count={HISTORY_COMMITS}", "--format=%x00%H %aI", "--", "."],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
    )


def _history_issue(state: dict[str, str], label: str, value: str) -> SecurityIssue:
    return SecurityIssue(
        "REPO-SEC-006", state["path"], 0,
        f"{label} was committed in {state['commit'][:12]} and is still in the git history.",
        details={"kind": label, "secret": mask(value), "commit": state["commit"], "committed_at": state["date"]},
    )


def history_secrets(root: Path, current: set[str], eligible: Callable[[str], bool]) -> list[SecurityIssue]:
    """Secrets added in past commits under ``root`` that are no longer in the working tree.

    ``eligible`` limits history to paths whose working-tree copy was searched, so a secret
    in a file that was skipped is never reported as removed.
    """
    process = _git_log(root)
    if process is None or process.stdout is None:
        return []
    timer = threading.Timer(HISTORY_SECONDS, process.kill)
    timer.start()
    issues: dict[str, SecurityIssue] = {}
    state = {"commit": "", "date": "", "path": ""}
    try:
        for raw in process.stdout:
            _history_line(raw.rstrip("\n"), state, issues, current, eligible)
    finally:
        timer.cancel()
        process.kill()
        process.wait()
    return list(issues.values())


def _history_line(line, state, issues, current, eligible) -> None:
    if line.startswith("\x00"):
        state["commit"], _, state["date"] = line[1:].partition(" ")
    elif line.startswith("+++ "):
        target = line[4:]
        state["path"] = target[2:] if target.startswith("b/") and eligible(target[2:]) else ""
    elif line.startswith("+") and state["path"]:
        for label, value in line_secrets(line[1:]):
            if value not in current and value not in issues:
                issues[value] = _history_issue(state, label, value)
