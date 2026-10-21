"""Infrastructure-as-code and CI configuration checks: Dockerfiles, Kubernetes, Terraform, GitHub Actions."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from backend.repository.code_issues import SecurityIssue, is_test_path
from backend.repository.iac.docker import dockerfile_issues
from backend.repository.iac.kubernetes import kubernetes_issues
from backend.repository.iac.terraform import terraform_issues
from backend.repository.iac.workflows import workflow_issues

_DOCKERFILE = re.compile(r"^(?:Dockerfile|Containerfile)(?:\..+)?$|\.(?:dockerfile|containerfile)$", re.IGNORECASE)
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")


def is_infrastructure_file(relative: str) -> bool:
    name = PurePosixPath(relative).name
    return bool(_DOCKERFILE.search(name)) or name.endswith((".tf", ".yml", ".yaml"))


def infrastructure_issues(relative: str, text: str) -> list[SecurityIssue]:
    """Misconfigurations in one infrastructure or workflow file; other files yield nothing."""
    if is_test_path(relative):
        return []
    name = PurePosixPath(relative).name
    if _DOCKERFILE.search(name):
        return dockerfile_issues(relative, text)
    if name.endswith(".tf"):
        return terraform_issues(relative, text)
    if _WORKFLOW.match(relative):
        return workflow_issues(relative, text)
    if name.endswith((".yml", ".yaml")):
        return kubernetes_issues(relative, text)
    return []
