import json
import shutil
from pathlib import Path

from backend.repository.ingest import application_from_report
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

    assert report["mendix"]["projects"] == ["App.mpr"]
    assert report["mendix"]["analyzed"] is False
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
    assert "Could not analyse" in report["mendix"]["reason"]


def test_mendix_findings_survive_ingest_and_sarif(tmp_path):
    root = _mendix_repository(tmp_path)
    report = scan_repository(root, {"name": "acme/portal"}, mendix_model=FIXTURE)
    report = json.loads(json.dumps(report))

    _, findings = application_from_report(report)
    mendix = [item for item in findings if item["rule_id"].startswith("MXSEC-")]
    assert mendix and {item["platform"] for item in mendix} == {"Mendix"}

    rules = {rule["id"]: rule for rule in to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["MXSEC-101"]["shortDescription"]["text"] != "MXSEC-101"
