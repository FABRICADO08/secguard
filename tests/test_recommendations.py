from backend.recommendations.engine import build_recommendations


def finding(rule_id, recommendation, severity="medium", finding_id="f1"):
    return {
        "id": finding_id,
        "rule_id": rule_id,
        "recommendation": recommendation,
        "category": "authorization",
        "severity": severity,
    }


def test_identical_recommendations_are_collapsed():
    recommendations = build_recommendations(
        [
            finding("MXSEC-101", "Restrict delete access.", finding_id="a"),
            finding("MXSEC-101", "Restrict delete access.", finding_id="b"),
        ]
    )

    assert len(recommendations) == 1
    assert recommendations[0]["finding_count"] == 2
    assert recommendations[0]["finding_ids"] == ["a", "b"]


def test_one_rule_can_emit_distinct_recommendations():
    recommendations = build_recommendations(
        [
            finding(
                "MXSEC-101",
                "Restrict delete access.",
                severity="critical",
                finding_id="a",
            ),
            finding(
                "MXSEC-101",
                "Review which roles require create access.",
                finding_id="b",
            ),
        ]
    )

    texts = [entry["recommendation"] for entry in recommendations]

    assert len(recommendations) == 2
    assert "Restrict delete access." in texts
    assert "Review which roles require create access." in texts


def test_recommendations_are_sorted_by_severity():
    recommendations = build_recommendations(
        [
            finding("GEN-001", "Low fix.", severity="low", finding_id="a"),
            finding(
                "GEN-002",
                "Critical fix.",
                severity="critical",
                finding_id="b",
            ),
        ]
    )

    assert recommendations[0]["recommendation"] == "Critical fix."


def test_findings_without_recommendation_are_skipped():
    assert build_recommendations([finding("GEN-003", "  ")]) == []
