import json

import pytest

from backend.config import settings
from backend.portfolio.objectives import clean, evaluate, gate, new_findings
from backend.repository.__main__ import main
from tests import test_github_auth as auth_tests

github = auth_tests.github


def finding(rule="REPO-SEC-001", location="app.py:10", severity="high", title="SQL injection"):
    return {"rule_id": rule, "location": location, "severity": severity, "title": title}


def report(findings=(), rating=4.0, counts=None, score=80):
    return {
        "findings": list(findings),
        "summary": {"severity_counts": counts or {}},
        "maintainability": {"rating": rating},
        "health": {"overall": {"score": score}},
    }


def test_clean_accepts_numbers_and_switches_off_empty_values():
    objectives, problem = clean({"max_critical": "0", "max_high": 3, "min_maintainability": 3.54, "min_health": ""})
    assert problem == ""
    assert objectives == {"max_critical": 0, "max_high": 3, "min_maintainability": 3.5, "min_health": None}


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"unknown": 1},
        {"max_critical": True},
        {"max_critical": "many"},
        {"max_high": 1.5},
        {"max_critical": -1},
        {"min_maintainability": 6},
        {"min_health": 101},
        {"min_health": {"value": 1}},
    ],
)
def test_clean_rejects_invalid_objectives(payload):
    objectives, problem = clean(payload)
    assert objectives == {} and problem


def test_evaluate_reports_met_missed_and_unmeasured():
    objectives = {"max_critical": 0, "max_high": 2, "min_maintainability": 3.5, "min_health": None}
    scan = {"severity_counts": {"critical": 1, "high": 2}, "maintainability": 4.1, "health": {}}
    status = evaluate(objectives, scan)
    assert status["met"] is False
    assert [(result["id"], result["met"]) for result in status["results"]] == [
        ("max_critical", False),
        ("max_high", True),
        ("min_maintainability", True),
    ]
    assert evaluate({"min_maintainability": 3.5}, {"maintainability": None})["met"] is None
    assert evaluate({"max_critical": None}, {})["met"] is None


def test_moved_findings_are_not_new_but_extra_copies_are():
    base = report([finding(location="app.py:10")])
    assert new_findings(report([finding(location="app.py:42")]), base) == []
    added = new_findings(report([finding(location="app.py:42"), finding(location="app.py:90")]), base)
    assert len(added) == 1
    assert new_findings(report([finding(severity="medium", rule="REPO-MNT-001")]), report()) == []


def test_mendix_findings_are_skipped_when_the_base_has_no_model():
    head = {**report([finding(rule="MXSEC-001", location="App.mpr")]), "mendix": {}}
    assert new_findings(head, report()) == []
    assert len(new_findings(head, {**report(), "mendix": {}})) == 1


def test_gate_fails_on_new_findings_and_rating_drops():
    result = gate(report([finding()], rating=3.5), report(rating=4.0), {})
    assert not result["passed"]
    assert len(result["problems"]) == 2
    assert gate(report(rating=3.9), report(rating=4.0), {})["passed"]
    assert gate(report([finding()]), report(), {}, severity="none")["passed"]


def test_gate_only_fails_objectives_the_change_newly_misses():
    objectives = {"max_critical": 0, "min_maintainability": 3.5}
    already_missed = report(counts={"critical": 2}, rating=3.0)
    assert gate(already_missed, already_missed, objectives)["passed"]
    result = gate(report(counts={"critical": 1}), report(), objectives, severity="none")
    assert result["problems"] == ["Objective missed: Critical findings at most 0 (now 1)."]


def test_gate_command_exit_code_and_summary(tmp_path, capsys):
    head, base, summary = tmp_path / "head.json", tmp_path / "base.json", tmp_path / "summary.md"
    base.write_text(json.dumps(report()))
    head.write_text(json.dumps(report(rating=4.0)))
    arguments = ["gate", "--report", str(head), "--baseline", str(base), "--summary", str(summary)]
    assert main(arguments) == 0
    head.write_text(json.dumps(report([finding()])))
    assert main([*arguments, "--max-critical", ""]) == 1
    assert "1 new finding(s) at or above high severity." in summary.read_text()
    assert "REPO-SEC-001" in capsys.readouterr().out
    head.write_text(json.dumps(report(counts={"high": 3})))
    assert main([*arguments, "--new-severity", "none", "--max-high", "2"]) == 1


def test_objectives_api_defaults_update_and_validation(client):
    data = client.get("/api/objectives").get_json()
    assert data["objectives"]["max_critical"] == 0 and data["can_edit"] is True
    response = client.put("/api/objectives", json={"min_maintainability": 3.5, "max_critical": 0})
    assert response.status_code == 200
    assert client.get("/api/objectives").get_json()["objectives"]["min_maintainability"] == 3.5
    assert client.put("/api/objectives", json={"min_health": 200}).status_code == 400
    assert client.get("/api/objectives").get_json()["objectives"]["min_health"] is None


def test_only_administrators_change_objectives(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    assert client.get("/api/objectives").get_json()["can_edit"] is False
    assert client.put("/api/objectives", json={"max_critical": 5}).status_code == 403
    response = client.put("/api/objectives", json={"max_critical": 5}, headers={"X-API-Key": "token"})
    assert response.status_code == 200


def test_github_admins_change_objectives_and_others_cannot(client, github, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    assert client.get("/api/objectives").status_code == 401
    auth_tests.sign_in(client)
    assert client.put("/api/objectives", json={"max_critical": 1}).status_code == 403
    monkeypatch.setattr(settings, "ADMINS", frozenset({"octo"}))
    assert client.put("/api/objectives", json={"max_critical": 1}).status_code == 200


def test_applications_list_shows_objective_status(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    auth_tests.ingest(client, tmp_path, "acme/api")
    client.put("/api/objectives", json={"max_critical": 0, "min_health": 100})
    data = client.get("/api/repositories").get_json()
    assert data["objectives"]["min_health"] == 100
    status = data["repositories"][0]["latest_scan"]["objectives"]
    assert [result["id"] for result in status["results"]] == ["max_critical", "min_health"]
    assert status["results"][0]["met"] is True
