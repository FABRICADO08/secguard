"""
Open a GitHub pull request that upgrades vulnerable dependencies.

The edits are applied to the manifests as they are on the default branch
now, not as they were when scanned, so a declaration that has changed
since is left alone. The signed-in user's GitHub token makes the branch,
commits and pull request, so GitHub records them under that user.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import quote

from backend.repository.upgrades import Upgrade, apply_upgrades
from backend.security import github_auth

MESSAGES = {
    "branch_exists": ("A SecGuard fix branch for this scan already exists. Merge or delete it first.", 409),
    "forbidden": ("GitHub refused the change. Check your write access to the repository.", 403),
    "refused": ("GitHub refused the change.", 502),
    "stale": ("The default branch no longer declares these versions. Run a new scan.", 409),
}


class FixError(RuntimeError):
    """A GitHub refusal; ``reason`` names its entry in ``MESSAGES``."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class FixRequest:
    token: str
    repository: str
    base: str
    branch: str


def _call(fix: FixRequest, method: str, path: str, missing_ok: bool = False, **kwargs) -> dict | None:
    response = github_auth._api(method, f"/repos/{fix.repository}{path}", fix.token, **kwargs)
    if missing_ok and response.status_code == 404:
        return None
    if response.status_code == 422 and method == "POST" and path == "/git/refs":
        raise FixError("branch_exists")
    if response.status_code in (401, 403, 404):
        raise FixError("forbidden")
    if not response.ok:
        raise FixError("refused")
    return response.json() if response.content else {}


def _edits(fix: FixRequest, upgrades: list[Upgrade]) -> list[tuple[str, str, str, list[Upgrade]]]:
    by_manifest: dict[str, list[Upgrade]] = {}
    for upgrade in upgrades:
        by_manifest.setdefault(upgrade.manifest, []).append(upgrade)
    edits = []
    for manifest, planned in by_manifest.items():
        document = _call(fix, "GET", f"/contents/{quote(manifest)}", missing_ok=True, params={"ref": fix.base})
        if document is None:
            continue
        text = base64.b64decode(document.get("content") or "").decode("utf-8")
        changed, applied = apply_upgrades(text, planned)
        if applied:
            edits.append((manifest, document["sha"], changed, applied))
    return edits


def _body(applied: list[Upgrade]) -> str:
    rows = "\n".join(
        f"| `{item.name}` | `{item.manifest}` | `{item.spec}` | `{item.new_spec()}` | "
        f"{', '.join(item.advisories) or '-'} |{' major upgrade' if item.breaking else ''}"
        for item in applied
    )
    notes = "\n\nRegenerate the lockfile (`npm install`) before merging." if any(
        item.ecosystem == "npm" for item in applied
    ) else ""
    return (
        "SecGuard found known vulnerabilities in these dependencies. Each one moves to the smallest "
        "release that clears every known advisory.\n\n"
        "| Package | Manifest | From | To | Advisories |\n|---|---|---|---|---|\n"
        f"{rows}{notes}"
    )


def _delete_branch(fix: FixRequest) -> None:
    try:
        github_auth._api("DELETE", f"/repos/{fix.repository}/git/refs/heads/{quote(fix.branch)}", fix.token)
    except github_auth.requests.RequestException:
        pass


def _commit(fix: FixRequest, edits: list[tuple[str, str, str, list[Upgrade]]]) -> None:
    for manifest, sha, text, items in edits:
        _call(fix, "PUT", f"/contents/{quote(manifest)}", json={
            "message": "Upgrade " + ", ".join(f"{item.name} to {item.target}" for item in items),
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": fix.branch,
        })


def open_fix_pull_request(fix: FixRequest, upgrades: list[Upgrade]) -> dict:
    """
    Create the branch, commit each manifest and open the pull request.

    A failure after the branch exists deletes it again, so a retry is not
    refused as an existing fix branch.
    """
    edits = _edits(fix, upgrades)
    if not edits:
        raise FixError("stale")
    head = _call(fix, "GET", f"/git/ref/heads/{quote(fix.base)}")
    _call(fix, "POST", "/git/refs", json={"ref": f"refs/heads/{fix.branch}", "sha": head["object"]["sha"]})
    applied = [upgrade for _, _, _, items in edits for upgrade in items]
    try:
        _commit(fix, edits)
        pull = _call(fix, "POST", "/pulls", json={
            "title": f"Upgrade {len(applied)} vulnerable dependenc{'y' if len(applied) == 1 else 'ies'}",
            "head": fix.branch,
            "base": fix.base,
            "body": _body(applied),
        })
    except (FixError, github_auth.requests.RequestException):
        _delete_branch(fix)
        raise
    return {"url": pull.get("html_url", ""), "number": pull.get("number"), "upgrades": [item.to_dict() for item in applied]}
