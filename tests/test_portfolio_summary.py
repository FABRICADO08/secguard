from datetime import datetime, timezone

from backend.portfolio.summary import portfolio_summary, rating_for

TODAY = datetime(2026, 9, 21, tzinfo=timezone.utc)


def scan(
    identifier,
    url,
    moment,
    risk_score=0,
):
    return {
        "id": identifier,
        "name": url,
        "url": url,
        "platform": "Generic",
        "status": "discovered",
        "created_at": moment,
        "updated_at": moment,
        "risk_score": risk_score,
        "risk_grade": "C",
    }


def finding(rule_id, severity="high", location="/"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "location": location,
        "title": rule_id,
    }


def summarize(applications, findings, **kwargs):
    return portfolio_summary(
        applications,
        lambda identifier: findings.get(identifier, []),
        today=TODAY,
        **kwargs,
    )


def test_a_rating_spans_five_stars_down_to_half_a_star():
    assert rating_for(0) == 5.0
    assert rating_for(100) == 0.5
    assert rating_for(50) == 2.8


def test_repeated_scans_of_one_target_collapse_into_one_system():
    applications = [
        scan("older", "https://app.test", "2026-08-01T00:00:00+00:00"),
        scan("newer", "https://app.test", "2026-09-01T00:00:00+00:00"),
    ]

    result = summarize(applications, {})

    assert [system["id"] for system in result["systems"]] == ["newer"]
    assert result["systems"][0]["scan_count"] == 2


def test_a_trailing_slash_does_not_split_a_system_in_two():
    applications = [
        scan("a", "https://app.test", "2026-08-01T00:00:00+00:00"),
        scan("b", "https://app.test/", "2026-09-01T00:00:00+00:00"),
    ]

    assert len(summarize(applications, {})["systems"]) == 1


def test_activity_compares_the_latest_scan_with_its_predecessor():
    applications = [
        scan("first", "https://app.test", "2026-08-01T00:00:00+00:00"),
        scan("second", "https://app.test", "2026-09-01T00:00:00+00:00"),
    ]

    findings = {
        "first": [finding("GEN-HDR-001"), finding("GEN-SES-001")],
        "second": [finding("GEN-HDR-001"), finding("GEN-CSP-001")],
    }

    activity = summarize(applications, findings)["systems"][0]["activity"]

    assert activity == {"new": 1, "existing": 1, "resolved": 1}


def test_a_first_scan_reports_every_finding_as_new():
    applications = [
        scan("only", "https://app.test", "2026-09-01T00:00:00+00:00")
    ]

    findings = {"only": [finding("GEN-HDR-001")]}

    activity = summarize(applications, findings)["systems"][0]["activity"]

    assert activity == {"new": 1, "existing": 0, "resolved": 0}


def test_severity_deltas_are_measured_against_the_previous_scan():
    applications = [
        scan("first", "https://app.test", "2026-08-01T00:00:00+00:00"),
        scan("second", "https://app.test", "2026-09-01T00:00:00+00:00"),
    ]

    findings = {
        "first": [finding("GEN-HDR-001", "critical")],
        "second": [
            finding("GEN-HDR-001", "critical"),
            finding("GEN-CSP-001", "critical"),
        ],
    }

    system = summarize(applications, findings)["systems"][0]

    assert system["severity_deltas"]["critical"] == 1
    assert system["severity_counts"]["critical"] == 2


def test_the_trend_buckets_each_scan_into_the_month_it_ran():
    applications = [
        scan("first", "https://app.test", "2026-08-01T00:00:00+00:00"),
        scan("second", "https://app.test", "2026-09-01T00:00:00+00:00"),
    ]

    findings = {
        "first": [finding("GEN-HDR-001"), finding("GEN-SES-001")],
        "second": [finding("GEN-HDR-001")],
    }

    trend = {
        entry["month"]: entry
        for entry in summarize(applications, findings)["trend"]
    }

    assert len(trend) == 12
    assert trend["2026-08"]["new"] == 2
    assert trend["2026-09"] == {
        "month": "2026-09",
        "new": 0,
        "existing": 1,
        "resolved": 1,
    }
    assert trend["2026-07"]["new"] == 0


def test_the_trend_window_ends_on_the_current_month():
    months = [entry["month"] for entry in summarize([], {})["trend"]]

    assert months[-1] == "2026-09"
    assert months[0] == "2025-10"


def test_scans_older_than_the_window_stay_out_of_the_trend():
    applications = [
        scan("ancient", "https://app.test", "2024-01-01T00:00:00+00:00")
    ]

    result = summarize(applications, {"ancient": [finding("GEN-HDR-001")]})

    assert sum(entry["new"] for entry in result["trend"]) == 0
    assert result["systems"][0]["total_findings"] == 1


def test_totals_aggregate_every_system():
    applications = [
        scan("a", "https://a.test", "2026-09-01T00:00:00+00:00", 90),
        scan("b", "https://b.test", "2026-09-02T00:00:00+00:00", 10),
    ]

    findings = {
        "a": [finding("GEN-HDR-001", "critical")],
        "b": [finding("GEN-SES-001", "low")],
    }

    totals = summarize(applications, findings)["totals"]

    assert totals["systems"] == 2
    assert totals["findings"] == 2
    assert totals["severity_counts"]["critical"] == 1
    assert totals["severity_counts"]["low"] == 1
    assert totals["activity"]["new"] == 2


def test_systems_are_ranked_by_risk():
    applications = [
        scan("low", "https://b.test", "2026-09-01T00:00:00+00:00", 10),
        scan("high", "https://a.test", "2026-09-01T00:00:00+00:00", 90),
    ]

    result = summarize(applications, {})

    assert [system["id"] for system in result["systems"]] == [
        "high",
        "low",
    ]
