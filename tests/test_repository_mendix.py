import json
import shutil
from pathlib import Path

import pytest

from backend.repository.ingest import InvalidReportError, application_from_report
from backend.repository.mendix import find_projects
from backend.repository.sarif import to_sarif
from backend.repository.scanner import scan_repository

FIXTURE = Path(__file__).parent / "fixtures" / "mendix_model_access.json"


def _mendix_repository(tmp_path):
    (tmp_path / "App.mpr").write_bytes(b"")
    (tmp_path / "node_modules" / "widget").mkdir(parents=True)
    (tmp_path / "node_modules" / "widget" / "Bundled.mpr").write_bytes(b"")
    return tmp_path


def test_find_projects_skips_vendored_directories(tmp_path):
    assert find_projects(_mendix_repository(tmp_path)) == ["App.mpr"]


def test_repository_without_mendix_has_no_mendix_section(tmp_path):
    assert "mendix" not in scan_repository(tmp_path)


def test_project_without_export_is_reported_as_not_analysed(tmp_path):
    report = scan_repository(_mendix_repository(tmp_path))

    assert [item["path"] for item in report["mendix"]["projects"]] == ["App.mpr"]
    assert report["mendix"]["analyzed"] is False
    assert report["mendix"]["projects"][0]["reason"]
    assert not [item for item in report["findings"] if item["rule_id"].startswith("MXSEC-")]


def test_export_findings_are_located_at_the_project(tmp_path):
    root = _mendix_repository(tmp_path)
    model = tmp_path / "export.json"
    shutil.copy(FIXTURE, model)

    report = scan_repository(root, {"name": "acme/portal"}, mendix_model=model)

    mendix = [item for item in report["findings"] if item["rule_id"].startswith("MXSEC-")]
    assert report["mendix"]["analyzed"] is True
    assert report["mendix"]["findings"] == len(mendix) > 0
    assert {item["location"] for item in mendix} == {"App.mpr"}
    assert all(item["evidence"]["element"] in item["title"] for item in mendix)
    assert report["health"]["security"]["score"] < 100


def test_unreadable_export_is_reported_without_failing(tmp_path):
    root = _mendix_repository(tmp_path)
    model = tmp_path / "export.json"
    model.write_text("not json", encoding="utf-8")

    report = scan_repository(root, mendix_model=model)

    assert report["mendix"]["analyzed"] is False
    assert "Could not analyse" in report["mendix"]["projects"][0]["reason"]


def test_mendix_findings_survive_ingest_and_sarif(tmp_path):
    root = _mendix_repository(tmp_path)
    report = scan_repository(root, {"name": "acme/portal"}, mendix_model=FIXTURE)
    report = json.loads(json.dumps(report))

    _, findings = application_from_report(report)
    mendix = [item for item in findings if item["rule_id"].startswith("MXSEC-")]
    assert mendix and {item["platform"] for item in mendix} == {"Mendix"}

    rules = {rule["id"]: rule for rule in to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["MXSEC-101"]["shortDescription"]["text"] != "MXSEC-101"


def _two_projects(tmp_path):
    for name in ("billing/Billing.mpr", "orders/Orders.mpr", "releases/Backup.mpr"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_each_project_is_analysed_from_its_own_export(tmp_path):
    root = _two_projects(tmp_path / "repo")
    exports = tmp_path / "exports"
    (exports / "orders").mkdir(parents=True)
    shutil.copy(FIXTURE, exports / "orders" / "Orders.mpr.json")

    report = scan_repository(root, mendix_model=exports)

    status = {item["path"]: item["analyzed"] for item in report["mendix"]["projects"]}
    assert status == {"billing/Billing.mpr": False, "orders/Orders.mpr": True}
    assert report["mendix"]["analyzed"] is False
    assert {item["location"] for item in report["findings"] if item["rule_id"].startswith("MXSEC-")} == {
        "orders/Orders.mpr"
    }


def test_single_export_is_not_guessed_onto_several_projects(tmp_path):
    report = scan_repository(_two_projects(tmp_path), mendix_model=FIXTURE)

    assert not any(item["analyzed"] for item in report["mendix"]["projects"])
    assert not [item for item in report["findings"] if item["rule_id"].startswith("MXSEC-")]


def _ingestable(tmp_path):
    report = scan_repository(_mendix_repository(tmp_path), {"name": "acme/portal"}, mendix_model=FIXTURE)
    return json.loads(json.dumps(report))


def test_ingest_keeps_the_mendix_status(tmp_path):
    report = _ingestable(tmp_path)

    application, _ = application_from_report(report)

    assert application.repository["mendix"]["projects"][0]["path"] == "App.mpr"
    assert application.repository["mendix"]["analyzed"] is True


@pytest.mark.parametrize(
    "forge",
    [
        lambda report: report.pop("mendix"),
        lambda report: report["mendix"]["projects"][0].update(analyzed=False),
        lambda report: report["findings"][0].update(location="Other.mpr"),
        lambda report: report["findings"][0].update(rule_id="MXSEC-999"),
    ],
)
def test_ingest_rejects_mendix_findings_without_an_analysed_project(tmp_path, forge):
    report = _ingestable(tmp_path)
    assert report["findings"][0]["rule_id"].startswith("MXSEC-")
    forge(report)

    with pytest.raises(InvalidReportError):
        application_from_report(report)
