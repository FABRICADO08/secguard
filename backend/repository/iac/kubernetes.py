"""Kubernetes manifest checks: host-level privileges, root containers and missing resource limits."""

from __future__ import annotations

import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

_WORKLOAD = re.compile(r"^kind:\s*[\"']?(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|ReplicationController)\b", re.MULTILINE)
_HOST_ACCESS = re.compile(r"^\s*-?\s*(?:(privileged|hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation):\s*true\b|(hostPath):)")
_ROOT_USER = re.compile(r"^\s*-?\s*runAsUser:\s*0\s*(?:#.*)?$")
_NON_ROOT = re.compile(r"^\s*-?\s*runAsNonRoot:\s*true\b", re.MULTILINE)
_LIMITS = re.compile(r"^\s*limits:", re.MULTILINE)


def _documents(text: str) -> list[tuple[int, str]]:
    """(first line number, text) for each YAML document."""
    documents, start, current = [], 1, []
    for number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^---\s*$", line):
            documents.append((start, "\n".join(current)))
            start, current = number + 1, []
        else:
            current.append(line)
    documents.append((start, "\n".join(current)))
    return documents


def _line_issues(path: str, start: int, document: str) -> list[SecurityIssue]:
    issues = []
    for offset, line in enumerate(document.splitlines()):
        if suppressed(line):
            continue
        host = _HOST_ACCESS.match(line)
        if host:
            setting = host.group(1) or host.group(2)
            issues.append(SecurityIssue("REPO-IAC-005", path, start + offset,
                                        f"`{setting}` gives the workload access to the node it runs on.", snippet(line)))
        elif _ROOT_USER.match(line):
            issues.append(SecurityIssue("REPO-IAC-006", path, start + offset,
                                        "`runAsUser: 0` runs the container as root.", snippet(line)))
    return issues


def _document_issues(path: str, start: int, document: str) -> list[SecurityIssue]:
    kind = _WORKLOAD.search(document)
    if not kind or not re.search(r"^\s*containers:", document, re.MULTILINE) or "secguard-ignore" in document:
        return []
    line = start + document[: kind.start()].count("\n")
    issues = _line_issues(path, start, document)
    if not _NON_ROOT.search(document) and not any(issue.rule_id == "REPO-IAC-006" for issue in issues):
        issues.append(SecurityIssue("REPO-IAC-006", path, line,
                                    f"{kind.group(1)} does not set `runAsNonRoot: true`, so its containers may run as root.",
                                    f"kind: {kind.group(1)}"))
    if not _LIMITS.search(document):
        issues.append(SecurityIssue("REPO-IAC-007", path, line,
                                    f"{kind.group(1)} sets no resource limits, so one container can starve the node.",
                                    f"kind: {kind.group(1)}"))
    return issues


def kubernetes_issues(path: str, text: str) -> list[SecurityIssue]:
    if not re.search(r"^apiVersion:", text, re.MULTILINE):
        return []
    issues = []
    for start, document in _documents(text):
        issues += _document_issues(path, start, document)
    return sorted(issues, key=lambda issue: issue.line)
