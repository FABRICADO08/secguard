"""Turn an uploaded repository report into a stored application record."""

from __future__ import annotations

import re
from typing import Any

from backend.model.application import Application
from backend.recommendations import build_recommendations
from backend.repository.findings import PLATFORM, RULE_CATALOGUE
from backend.repository.scanner import SCHEMA
from backend.risk.scoring import summarize
from backend.rules.base import Finding

REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$")

class InvalidReportError(ValueError):
    """The uploaded document is not a usable repository report."""


_FINDING_FIELDS = ("rule_id", "title", "severity", "description", "recommendation", "confidence", "location", "references", "evidence")


def _clean_finding(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InvalidReportError("Every finding must be an object.")

    rule_id = raw.get("rule_id")

    if rule_id not in RULE_CATALOGUE:
        raise InvalidReportError(f"Unknown repository rule '{rule_id}'.")

    values = {name: raw.get(name) for name in _FINDING_FIELDS if raw.get(name) is not None}

    if not isinstance(values.get("references", []), list) or not isinstance(values.get("evidence", {}), dict):
        raise InvalidReportError("Finding references must be a list and evidence an object.")

    for name in ("title", "severity", "description", "recommendation", "confidence", "location"):
        if name in values and not isinstance(values[name], str):
            raise InvalidReportError(f"Finding field '{name}' must be a string.")

    metadata = RULE_CATALOGUE[rule_id]

    # Category, platform, CWE and OWASP mapping are owned by the server;
    # risk is recomputed rather than trusted.
    return Finding(
        **{"title": metadata["title"], "severity": "medium", **values},
        category=metadata["category"],
        platform=PLATFORM,
        cwe=metadata["cwe"],
        owasp=metadata["owasp"],
    ).to_dict()


def application_from_report(report: Any) -> tuple[Application, list[dict[str, Any]]]:
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise InvalidReportError(f"Expected a SecGuard repository report with schema '{SCHEMA}'.")

    repository = report.get("repository")

    if not isinstance(repository, dict):
        raise InvalidReportError("The report has no repository section.")

    name = str(repository.get("name") or "")

    if not REPOSITORY_NAME.match(name):
        raise InvalidReportError("Repository name must look like 'owner/repo'.")

    raw_findings = report.get("findings") or []
    quality = report.get("quality") or {}

    if not isinstance(raw_findings, list) or not isinstance(quality, dict) or not isinstance(quality.get("findings") or [], list):
        raise InvalidReportError("Findings must be lists.")

    findings = [_clean_finding(item) for item in raw_findings]
    quality_findings = [_clean_finding(item) for item in quality.get("findings") or []]

    provider = "github" if repository.get("provider") == "github" else "repository"

    application = Application.create(
        requested_url=f"{provider}://{name}",
        final_url=str(repository.get("url") or f"{provider}://{name}"),
        name=name.rsplit("/", 1)[-1],
    )

    application.platform = PLATFORM
    application.status = "analyzed"

    application.security = {
        **summarize(findings),
        "findings": findings,
        "recommendations": build_recommendations(findings),
        "rules_evaluated": len(RULE_CATALOGUE),
        "rule_errors": [],
    }

    application.repository = {
        key: report.get(key)
        for key in ("schema", "generated_at", "repository", "statistics", "dependencies", "vulnerabilities", "licenses", "freshness", "health")
    }

    application.repository["quality"] = {
        "metrics": quality.get("metrics") or {},
        "hotspots": quality.get("hotspots") or [],
        "findings": quality_findings,
    }

    return application, findings
