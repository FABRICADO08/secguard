import pytest

from backend.config import settings
from backend.portfolio.teams import clean, granted, teams_for
from tests import test_github_auth as auth_tests

github = auth_tests.github

TEAMS = {"teams": [
    {"name": "Payments", "business_unit": "Retail", "applications": ["Acme/Billing", "acme/api"], "members": ["Octo"]},
    {"name": "Platform", "applications": ["acme/docs"]},
]}


def test_clean_normalises_teams():
    teams, problem = clean(TEAMS)
    assert problem == ""
    assert teams[0] == {"id": "payments", "name": "Payments", "business_unit": "Retail",
                        "applications": ["acme/api", "acme/billing"], "members": ["octo"]}
    assert teams[1]["members"] == [] and teams[1]["business_unit"] == ""


@pytest.mark.parametrize("payload", [
    None, [], {"teams": {}}, {"teams": [1]}, {"teams": [{"name": " "}]}, {"teams": [{"name": "x" * 81}]},
    {"teams": [{"name": "A", "applications": ["no-slash"]}]}, {"teams": [{"name": "A", "members": ["bad login!"]}]},
    {"teams": [{"name": "A", "members": "octo"}]}, {"teams": [{"name": "Ops"}, {"name": "ops"}]},
])
def test_clean_rejects_invalid_teams(payload):
    teams, problem = clean(payload)
    assert teams == [] and problem


def test_membership_grants_and_team_lookup():
    teams, _ = clean(TEAMS)
    assert granted("OCTO", teams) == {"acme/api", "acme/billing"}
    assert granted("other", teams) == set()
    assert clean({"teams": [{"name": "A", "members": ["x"]}]})[0][0]["members"] == ["x"]
    assert [team["name"] for team in teams_for("ACME/API", teams)] == ["Payments"]


def test_only_administrators_change_teams(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    assert client.put("/api/teams", json=TEAMS).status_code == 403
    admin = {"X-API-Key": "token"}
    assert client.put("/api/teams", json={"teams": [{"name": ""}]}, headers=admin).status_code == 400
    data = client.put("/api/teams", json=TEAMS, headers=admin).get_json()
    assert [team["id"] for team in data["teams"]] == ["payments", "platform"] and data["can_edit"] is True
    assert client.get("/api/teams", headers=admin).get_json()["teams"][0]["members"] == ["octo"]


def test_team_membership_grants_read_only_access(client, github, tmp_path, monkeypatch):
    billing = auth_tests.ingest(client, tmp_path, "acme/billing")
    auth_tests.ingest(client, tmp_path, "acme/api")
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    auth_tests.sign_in(client)
    assert client.get(f"/api/applications/{billing}").status_code == 404
    client.put("/api/teams", json=TEAMS, headers={"X-API-Key": "token"})
    assert client.get(f"/api/applications/{billing}").status_code == 200
    _assert_granted_application_is_read_only(client)
    _assert_members_are_hidden_from_non_admins(client)


def _assert_granted_application_is_read_only(client):
    items = {item["name"]: item for item in client.get("/api/repositories").get_json()["repositories"]}
    assert items["acme/billing"]["can_trigger"] is False and items["acme/billing"]["can_rename"] is False
    assert [team["name"] for team in items["acme/api"]["teams"]] == ["Payments"]
    assert client.post("/api/repositories/acme/billing/scan").status_code in (403, 404)


def _assert_members_are_hidden_from_non_admins(client):
    teams = client.get("/api/teams").get_json()
    assert teams["can_edit"] is False and teams["teams"][0]["members"] == []
    assert teams["teams"][1]["applications"] == ["acme/docs"]


def test_signed_out_users_cannot_read_teams(client, github, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    assert client.get("/api/teams").status_code == 401


def test_portfolio_pdf_filters_by_team(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    auth_tests.ingest(client, tmp_path, "acme/api")
    client.put("/api/teams", json=TEAMS)
    response = client.get("/api/reports/portfolio.pdf?team=payments")
    assert response.status_code == 200 and response.data.startswith(b"%PDF")
    assert client.get("/api/reports/portfolio.pdf?team=missing").status_code == 404
    assert client.get("/api/reports/portfolio.pdf?unit=Retail").data.startswith(b"%PDF")
    assert client.get("/api/reports/portfolio.pdf?unit=Missing").status_code == 404
