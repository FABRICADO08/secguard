"""SARIF 2.1.0 export, the format GitHub code scanning ingests."""

from __future__ import annotations

import hashlib
from typing import Any

from backend.repository.findings import QUALITY_RECOMMENDATIONS, RULE_CATALOGUE
from backend.repository.sbom import TOOL_NAME, TOOL_VERSION

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}

SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0", "informational": "0.0"}


def split_location(location: str) -> tuple[str, int]:
    path, _, line = (location or "").rpartition(":")

    if path and line.isdigit():
        return path, int(line)

    return location or "", 0


def _result(finding: dict[str, Any], rule_index: dict[str, int], fallback: str) -> dict[str, Any]:
    path, line = split_location(str(finding.get("location") or ""))

    # Code scanning rejects results without a location, so repository-wide
    # findings are anchored to the project's main manifest or README.
    if not path or path == "repository":
        path, line = fallback, 0

    severity = str(finding.get("severity") or "low")

    message = str(finding.get("description") or finding.get("title") or "")

    if finding.get("recommendation"):
        message += f"\n\nRemediation: {finding['recommendation']}"

    result: dict[str, Any] = {
        "ruleId": finding["rule_id"],
        "ruleIndex": rule_index[finding["rule_id"]],
        "level": LEVELS.get(severity, "note"),
        "message": {"text": message},
        "partialFingerprints": {
            "secguardFinding/v1": hashlib.sha256(
                f"{finding['rule_id']}|{finding.get('location')}|{finding.get('title')}".encode()
            ).hexdigest()
        },
        "properties": {"severity": severity, "confidence": finding.get("confidence", "")},
    }

    physical: dict[str, Any] = {"artifactLocation": {"uri": path}}

    end = (finding.get("evidence") or {}).get("end_line") or line

    if line:
        physical["region"] = {"startLine": line, "endLine": max(end, line)}

    result["locations"] = [{"physicalLocation": physical}]

    return result


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    fallback = next(
        (str(dependency.get("manifest")) for dependency in report.get("dependencies") or [] if dependency.get("manifest")),
        "README.md",
    )

    findings = [*(report.get("findings") or []), *((report.get("quality") or {}).get("findings") or [])]

    rule_ids = sorted({finding["rule_id"] for finding in findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    worst: dict[str, str] = {}

    for finding in findings:
        current = worst.get(finding["rule_id"], "informational")
        if float(SECURITY_SEVERITY.get(finding.get("severity"), "0")) >= float(SECURITY_SEVERITY[current]):
            worst[finding["rule_id"]] = finding.get("severity", "low")

    rules = []

    for rule_id in rule_ids:
        metadata = RULE_CATALOGUE.get(rule_id, {"title": rule_id, "category": "", "cwe": "", "owasp": ""})

        tags = [metadata["category"]] + [tag for tag in (metadata["cwe"], metadata["owasp"]) if tag]

        properties: dict[str, Any] = {"tags": [tag for tag in tags if tag]}

        if metadata["category"] != "maintainability":
            properties["tags"].append("security")
            properties["security-severity"] = SECURITY_SEVERITY.get(worst.get(rule_id, "low"), "2.0")

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": "".join(word.capitalize() for word in metadata["title"].replace("'", "").split()),
            "shortDescription": {"text": metadata["title"]},
            "defaultConfiguration": {"level": LEVELS.get(worst.get(rule_id, "low"), "note")},
            "properties": properties,
        }

        if rule_id in QUALITY_RECOMMENDATIONS:
            rule["help"] = {"text": QUALITY_RECOMMENDATIONS[rule_id]}

        rules.append(rule)

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/FABRICADO08/secguard",
                        "rules": rules,
                    }
                },
                "results": [_result(finding, rule_index, fallback) for finding in findings],
            }
        ],
    }
