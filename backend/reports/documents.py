"""PDF management reports for one application and for the whole portfolio."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.portfolio.objectives import SEVERITY_RANK, evaluate
from backend.reports.pdf import Document

MAX_FINDINGS = 40
_SEVERITIES = ("critical", "high", "medium", "low")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _score(aspect: dict[str, Any] | None) -> str:
    aspect = aspect or {}
    if aspect.get("score") is None:
        return "-"
    return f"{aspect['score']} ({aspect.get('grade', '-')})"


def _stars(value: Any) -> str:
    return "-" if value is None else f"{float(value):.1f} stars"


def _value(value: Any) -> str:
    if value is None:
        return "-"
    return str(int(value)) if float(value).is_integer() else f"{float(value):.1f}"


def _status(met: bool | None) -> str:
    return "Not measured" if met is None else "Met" if met else "Missed"


def scan_summary(application: dict[str, Any]) -> dict[str, Any]:
    """The objective-relevant fields of a stored application record."""
    repository = application.get("repository") or {}
    return {
        "severity_counts": (application.get("security") or {}).get("severity_counts") or {},
        "maintainability": (repository.get("maintainability") or {}).get("rating"),
        "health": repository.get("health") or {},
    }


def application_report(name: str, application: dict[str, Any], objectives: dict[str, Any]) -> bytes:
    repository = application.get("repository") or {}
    meta = repository.get("repository") or {}
    security = application.get("security") or {}
    health = repository.get("health") or {}
    counts = security.get("severity_counts") or {}
    findings = sorted(
        security.get("findings") or [],
        key=lambda finding: -SEVERITY_RANK.get(str(finding.get("severity")), 0),
    )

    document = Document(f"{name} - SecGuard application report")
    document.heading(f"{name}", 20)
    details = [f"Generated {_now()}"]
    if meta.get("name"):
        details.append(f"GitHub {meta['name']}")
    if meta.get("commit"):
        details.append(f"commit {str(meta['commit'])[:12]}")
    if repository.get("generated_at") or application.get("updated_at"):
        details.append(f"scanned {str(repository.get('generated_at') or application.get('updated_at'))[:16].replace('T', ' ')}")
    document.paragraph(" · ".join(details), 9)

    document.heading("Health")
    document.tiles(
        [
            ("Overall health", _score(health.get("overall"))),
            ("Security", _score(health.get("security"))),
            ("Open source", _score(health.get("open_source"))),
            ("Maintainability", _stars((repository.get("maintainability") or {}).get("rating"))),
        ]
    )
    document.tiles([(severity.capitalize(), str(counts.get(severity, 0))) for severity in _SEVERITIES])

    status = evaluate(objectives, scan_summary(application))
    document.heading("Objectives")
    if status["results"]:
        document.paragraph(f"Overall: {_status(status['met'])}", 10)
        document.gap(4)
        document.table(
            ["Objective", "Target", "Actual", "Status"],
            [[result["label"], _value(result["target"]), _value(result["actual"]), _status(result["met"])] for result in status["results"]],
            [0.46, 0.16, 0.16, 0.22],
        )
    else:
        document.paragraph("No objectives are configured.", 10)

    dependencies = repository.get("dependencies") or []
    vulnerable = [dependency for dependency in dependencies if dependency.get("vulnerabilities")]
    document.heading("Open source")
    document.paragraph(
        f"{len(dependencies)} dependencies, {len(vulnerable)} with known vulnerabilities "
        f"({len(repository.get('vulnerabilities') or [])} advisories).",
        10,
    )

    document.heading(f"Findings ({len(findings)})")
    if findings:
        document.table(
            ["Severity", "Finding", "Location"],
            [
                [str(finding.get("severity", "")).capitalize(), str(finding.get("title", "")), str(finding.get("location") or "-")]
                for finding in findings[:MAX_FINDINGS]
            ],
            [0.13, 0.52, 0.35],
        )
        if len(findings) > MAX_FINDINGS:
            document.gap(4)
            document.paragraph(f"...and {len(findings) - MAX_FINDINGS} more; see SecGuard for the full list.", 9)
    else:
        document.paragraph("No findings.", 10)
    return document.render()


def portfolio_report(rows: list[dict[str, Any]]) -> bytes:
    """``rows`` holds name, scan (an objective scan summary or None) and objectives status."""
    scanned = [row for row in rows if row["scan"] is not None]
    meeting = [row for row in scanned if row["objectives"]["met"]]
    measured = [row for row in scanned if row["objectives"]["met"] is not None]
    critical = sum((row["scan"]["severity_counts"] or {}).get("critical", 0) for row in scanned)
    high = sum((row["scan"]["severity_counts"] or {}).get("high", 0) for row in scanned)

    document = Document("SecGuard portfolio report")
    document.heading("Portfolio report", 20)
    document.paragraph(f"Generated {_now()} · {len(scanned)} of {len(rows)} applications scanned", 9)
    document.heading("Summary")
    document.tiles(
        [
            ("Applications", str(len(rows))),
            ("Meeting objectives", f"{len(meeting)} of {len(measured)}"),
            ("Critical findings", str(critical)),
            ("High findings", str(high)),
        ]
    )
    document.heading("Applications")
    table = []
    for row in rows:
        scan = row["scan"]
        if scan is None:
            table.append([row["name"], "Not scanned", "-", "-", "-", "-"])
            continue
        counts = scan["severity_counts"] or {}
        table.append(
            [
                row["name"],
                _score((scan["health"] or {}).get("overall")),
                _stars(scan["maintainability"]),
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
                _status(row["objectives"]["met"]),
            ]
        )
    document.table(
        ["Application", "Health", "Maintainability", "Critical", "High", "Objectives"],
        table,
        [0.32, 0.14, 0.17, 0.11, 0.09, 0.17],
    )
    return document.render()
