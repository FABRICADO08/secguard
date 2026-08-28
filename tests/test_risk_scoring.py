from backend.risk.scoring import (
    application_risk_score,
    finding_score,
    risk_grade,
    severity_counts,
    summarize,
)
from backend.risk.severity import (
    highest_severity,
    normalize_severity,
    severity_from_score,
)


def test_normalize_severity_maps_aliases():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("blocker") == "critical"
    assert normalize_severity("") == "informational"
    assert normalize_severity("nonsense") == "informational"


def test_finding_score_scales_with_confidence():
    confirmed = finding_score("high", "confirmed")
    tentative = finding_score("high", "tentative")

    assert confirmed > tentative
    assert finding_score("critical", "confirmed") == 90


def test_application_risk_score_is_driven_by_worst_finding():
    one_critical = application_risk_score(
        [{"severity": "critical", "confidence": "confirmed"}]
    )

    many_low = application_risk_score(
        [{"severity": "low", "confidence": "confirmed"}] * 10
    )

    assert one_critical > many_low


def test_application_risk_score_is_bounded():
    findings = [
        {"severity": "critical", "confidence": "confirmed"}
    ] * 25

    assert 0 <= application_risk_score(findings) <= 100


def test_empty_application_scores_zero():
    assert application_risk_score([]) == 0
    assert risk_grade(0) == "A"


def test_severity_counts_and_summary():
    findings = [
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "low"},
    ]

    counts = severity_counts(findings)

    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0

    summary = summarize(findings)

    assert summary["total_findings"] == 3
    assert summary["highest_severity"] == "high"
    assert summary["risk_grade"] in {"A", "B", "C", "D", "E"}


def test_severity_from_score_boundaries():
    assert severity_from_score(90) == "critical"
    assert severity_from_score(70) == "high"
    assert severity_from_score(45) == "medium"
    assert severity_from_score(20) == "low"
    assert severity_from_score(0) == "informational"


def test_highest_severity_of_mixed_values():
    assert highest_severity(["low", "critical", "medium"]) == "critical"
    assert highest_severity([]) == "informational"
