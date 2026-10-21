"""Dockerfile checks: root user, unpinned base images, baked-in secrets and unverified remote scripts."""

from __future__ import annotations

import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

_SECRET_NAME = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ash|dash)\b")
_ROOT_USERS = frozenset({"root", "0", "root:root", "0:0"})
_CREDENTIAL_ARGUMENTS = (
    (re.compile(r"(\s(?:-u|--user|-H|--header|--password|--http-password|--header=)\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(://)[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(https?://[^\s?#]+)\?\S+"), r"\1?[REDACTED]"),
)


def _instructions(text: str) -> list[tuple[int, str, str]]:
    """(line, INSTRUCTION, arguments) with continuation lines joined and comments dropped."""
    result: list[tuple[int, str, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if not buffer:
            start = number
        buffer += " " + line.rstrip("\\").strip()
        if line.endswith("\\"):
            continue
        parts = buffer.strip().split(None, 1)
        result.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buffer = ""
    return result


def _image(arguments: str) -> tuple[str, str]:
    words = [word for word in arguments.split() if not word.startswith("--")]
    image = words[0] if words else ""
    alias = words[2].lower() if len(words) > 2 and words[1].lower() == "as" else ""
    return image, alias


def _unpinned(image: str, aliases: set[str]) -> bool:
    if not image or image.lower() in aliases or image.lower() == "scratch" or "$" in image or "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


def _base_image_issues(path: str, steps: list[tuple[int, str, str]]) -> list[SecurityIssue]:
    issues, aliases = [], set()
    for line, instruction, arguments in steps:
        if instruction != "FROM":
            continue
        image, alias = _image(arguments)
        if _unpinned(image, aliases):
            issues.append(SecurityIssue(
                "REPO-IAC-002", path, line,
                f"Base image `{image}` has no version tag (or uses `latest`), so rebuilds can silently pull a different image.",
                f"FROM {image}",
            ))
        if alias:
            aliases.add(alias)
    return issues


def _stages(steps: list[tuple[int, str, str]]) -> list[list[tuple[int, str, str]]]:
    starts = [index for index, step in enumerate(steps) if step[1] == "FROM"]
    return [steps[start:end] for start, end in zip(starts, [*starts[1:], len(steps)])]


def _effective_user(stage: list[tuple[int, str, str]], users: dict[str, tuple[int, str] | None]) -> tuple[int, str] | None:
    """Last `USER` (line, name) in effect at the end of a stage, inheriting from a parent stage alias."""
    image, _ = _image(stage[0][2])
    own = [(line, arguments.strip()) for line, instruction, arguments in stage if instruction == "USER"]
    if own:
        return own[-1]
    return users.get(image.lower())


def _root_issue(path: str, steps: list[tuple[int, str, str]]) -> list[SecurityIssue]:
    stages = _stages(steps)
    if not stages:
        return []
    users: dict[str, tuple[int, str] | None] = {}
    for stage in stages:
        _, alias = _image(stage[0][2])
        if alias:
            users[alias] = _effective_user(stage, users)
    final = stages[-1]
    image, _ = _image(final[0][2])
    user = _effective_user(final, users)
    if user is None:
        if "nonroot" in image.lower():
            return []
        return [SecurityIssue("REPO-IAC-001", path, final[0][0],
                              "The final image stage has no `USER` instruction, so the container runs as root.", f"FROM {image}")]
    if user[1].lower() not in _ROOT_USERS:
        return []
    return [SecurityIssue("REPO-IAC-001", path, user[0], "The final stage runs as the root user.", f"USER {user[1]}")]


def _secret_issues(path: str, line: int, instruction: str, arguments: str) -> list[SecurityIssue]:
    if instruction not in ("ENV", "ARG"):
        return []
    pairs = re.findall(r"([A-Za-z_][\w.-]*)=(\"[^\"]*\"|'[^']*'|\S+)", arguments)
    if not pairs and instruction == "ENV" and len(arguments.split(None, 1)) == 2:
        pairs = [tuple(arguments.split(None, 1))]
    return [
        SecurityIssue("REPO-IAC-003", path, line, f"`{instruction} {name}` bakes a secret value into every image layer.",
                      f"{instruction} {name}=[REDACTED]")
        for name, value in pairs
        if _SECRET_NAME.search(name) and value.strip("\"'") and not value.strip("\"'").startswith("$")
    ]


def _remote_issues(path: str, line: int, instruction: str, arguments: str) -> list[SecurityIssue]:
    if instruction == "RUN" and _PIPE_TO_SHELL.search(arguments):
        message = "A script downloaded at build time is piped straight into a shell without checking its integrity."
    elif instruction == "ADD" and re.search(r"(?:^|\s)https?://", arguments) and "--checksum" not in arguments:
        message = "`ADD` downloads a remote file without a `--checksum`, so its contents are not verified."
    else:
        return []
    return [SecurityIssue("REPO-IAC-004", path, line, message, snippet(_without_credentials(f"{instruction} {arguments}")))]


def _without_credentials(command: str) -> str:
    for pattern, replacement in _CREDENTIAL_ARGUMENTS:
        command = pattern.sub(replacement, command)
    return command


def dockerfile_issues(path: str, text: str) -> list[SecurityIssue]:
    lines = text.splitlines()
    steps = [step for step in _instructions(text) if not suppressed(lines[step[0] - 1])]
    issues = _base_image_issues(path, steps) + _root_issue(path, steps)
    for line, instruction, arguments in steps:
        issues += _secret_issues(path, line, instruction, arguments)
        issues += _remote_issues(path, line, instruction, arguments)
    return sorted(issues, key=lambda issue: issue.line)
