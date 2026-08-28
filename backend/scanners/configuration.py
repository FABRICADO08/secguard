from __future__ import annotations

from typing import Any
from uuid import uuid4

import requests

from backend.discovery.http import absolute_url, build_session, probe

# Path -> what an exposed copy would leak. Signatures keep soft-404
# pages and SPA catch-all routes from being reported as real exposures.
SENSITIVE_PATHS: list[dict[str, Any]] = [
    {
        "path": "/.env",
        "label": "Environment file",
        "severity": "critical",
        "signatures": ["=", "_KEY", "_SECRET", "PASSWORD", "DB_"],
    },
    {
        "path": "/.git/config",
        "label": "Git repository configuration",
        "severity": "critical",
        "signatures": ["[core]", "repositoryformatversion", "[remote"],
    },
    {
        "path": "/.git/HEAD",
        "label": "Git repository HEAD",
        "severity": "critical",
        "signatures": ["ref:", "refs/heads"],
    },
    {
        "path": "/.svn/entries",
        "label": "Subversion metadata",
        "severity": "high",
        "signatures": ["dir", "svn"],
    },
    {
        "path": "/.DS_Store",
        "label": "macOS directory index",
        "severity": "low",
        "signatures": ["Bud1"],
    },
    {
        "path": "/web.config",
        "label": "IIS configuration",
        "severity": "high",
        "signatures": ["<configuration", "system.web"],
    },
    {
        "path": "/config.json",
        "label": "Application configuration",
        "severity": "medium",
        "signatures": ["{"],
    },
    {
        "path": "/server-status",
        "label": "Apache server status",
        "severity": "medium",
        "signatures": ["Apache Server Status", "Server uptime"],
    },
    {
        "path": "/phpinfo.php",
        "label": "PHP configuration dump",
        "severity": "high",
        "signatures": ["phpinfo()", "PHP Version"],
    },
    {
        "path": "/.well-known/security.txt",
        "label": "Security contact policy",
        "severity": "informational",
        "signatures": ["Contact:", "Expires:"],
    },
    {
        "path": "/backup.zip",
        "label": "Backup archive",
        "severity": "high",
        "signatures": [],
    },
    {
        "path": "/robots.txt",
        "label": "Robots policy",
        "severity": "informational",
        "signatures": ["user-agent", "disallow", "sitemap"],
    },
]


def baseline_response(
    base_url: str,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """
    Fetch a path that cannot exist.

    Its response is the fingerprint of "not found" for this target, which
    lets the scanner ignore servers that answer 200 for everything.
    """

    session = session or build_session()

    return probe(
        absolute_url(base_url, f"/secguard-baseline-{uuid4().hex}"),
        session,
    )


def _matches_baseline(
    result: dict[str, Any],
    baseline: dict[str, Any],
) -> bool:
    if baseline.get("status_code") != result.get("status_code"):
        return False

    # Same status and near-identical size means the server is serving its
    # catch-all page rather than the requested resource.
    baseline_length = baseline.get("content_length") or 0
    length = result.get("content_length") or 0

    return abs(baseline_length - length) <= max(32, baseline_length * 0.02)


def scan_exposed_paths(
    base_url: str,
    session: requests.Session | None = None,
) -> list[dict[str, Any]]:
    """Probe well-known sensitive paths and report the exposed ones."""

    session = session or build_session()

    baseline = baseline_response(base_url, session)

    exposures: list[dict[str, Any]] = []

    for entry in SENSITIVE_PATHS:
        url = absolute_url(base_url, entry["path"])

        result = probe(url, session)

        status = result.get("status_code")

        if status is None or not 200 <= status < 300:
            continue

        if _matches_baseline(result, baseline):
            continue

        body = str(result.get("body_preview") or "").lower()

        signatures = [
            signature
            for signature in entry["signatures"]
            if signature.lower() in body
        ]

        # A signature-backed hit is confirmed; a bare 200 is only a lead.
        if entry["signatures"] and not signatures:
            continue

        exposures.append(
            {
                "url": url,
                "path": entry["path"],
                "label": entry["label"],
                "severity": entry["severity"],
                "status_code": status,
                "content_type": result.get("content_type", ""),
                "content_length": result.get("content_length", 0),
                "matched_signatures": signatures,
                "confidence": "confirmed" if signatures else "tentative",
            }
        )

    return exposures
