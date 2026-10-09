import ast
import json
from datetime import datetime, timezone

import pytest

from backend import app as app_module
from backend.repository import licenses
from backend.repository.__main__ import main
from backend.repository.health import benchmark, grade, health_summary
from backend.repository.manifests import Dependency, discover_dependencies
from backend.repository.quality import (
    analyse_quality,
    cognitive_complexity,
    cyclomatic_complexity,
)
from backend.repository.reachability import (
    IMPORTED,
    NOT_IMPORTED,
    UNKNOWN,
    ReachabilityIndex,
)
from backend.repository.sarif import to_sarif
from backend.repository.sbom import cyclonedx, purl, spdx
from backend.repository.scanner import scan_repository
from backend.repository.suggestions import (
    build_review,
    commentable_lines,
    suggested_line,
)
from backend.repository.typosquat import damerau_levenshtein, typosquat_target
from backend.repository.versions import (
    NPM,
    PYPI,
    is_breaking_upgrade,
    newest_satisfying,
    satisfies,
)
from backend.storage import scans

TODAY = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _release(when):
    return [{"upload_time_iso_8601": when}]


REGISTRY = {
    "https://pypi.org/pypi/jinja2/json": {
        "info": {"license_expression": "BSD-3-Clause", "version": "3.1.6"},
        "releases": {
            "2.10": _release("2017-11-08T00:00:00Z"),
            "2.10.1": _release("2019-04-06T00:00:00Z"),
            "2.11.3": _release("2021-01-31T00:00:00Z"),
            "3.1.6": _release("2025-03-05T00:00:00Z"),
        },
    },
    "https://pypi.org/pypi/flask/json": {
        "info": {"license_expression": "BSD-3-Clause", "version": "3.1.0"},
        "releases": {"3.0.0": _release("2023-09-30T00:00:00Z"), "3.1.0": _release("2024-11-13T00:00:00Z")},
    },
    "https://pypi.org/pypi/oldlib/json": {
        "info": {"license": "GPL-3.0-only", "version": "1.0"},
        "releases": {"1.0": _release("2019-01-01T00:00:00Z")},
    },
    "https://registry.npmjs.org/lodash": {
        "dist-tags": {"latest": "4.17.21"},
        "versions": {"4.17.21": {"license": "MIT"}},
        "time": {"created": "2012-04-23T00:00:00Z", "4.17.15": "2019-07-19T00:00:00Z", "4.17.21": "2021-02-20T00:00:00Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}],
    },
    "https://registry.npmjs.org/left-pad": {
        "dist-tags": {"latest": "1.3.0"},
        "versions": {"1.3.0": {"license": "WTFPL", "deprecated": "use String.prototype.padStart()"}},
        "time": {"created": "2014-03-14T00:00:00Z", "1.3.0": "2018-04-09T00:00:00Z"},
        "maintainers": [{"name": "a"}],
    },
    "https://registry.npmjs.org/expresss": {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"license": "MIT"}},
        "time": {"created": "2026-09-20T00:00:00Z", "1.0.0": "2026-09-20T00:00:00Z"},
        "maintainers": [{"name": "x"}],
    },
    "https://api.npmjs.org/downloads/point/last-week/expresss": {"downloads": 12},
}

OSV = {
    "GHSA-jinja": {
        "id": "GHSA-jinja",
        "summary": "Sandbox escape",
        "aliases": ["CVE-2019-10906", "PYSEC-jinja"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
    },
    "PYSEC-jinja": {
        "id": "PYSEC-jinja",
        "aliases": ["CVE-2019-10906", "GHSA-jinja"],
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
    },
    "GHSA-lodash": {
        "id": "GHSA-lodash",
        "summary": "Prototype pollution",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}],
    },
}


def fake_fetch(url):
    if url.startswith("https://api.osv.dev/v1/vulns/"):
        return OSV.get(url.rsplit("/", 1)[-1])
    return REGISTRY.get(url)


def fake_post(_url, payload):
    hits = {("jinja2", "2.10"): ["GHSA-jinja", "PYSEC-jinja"], ("lodash", "4.17.15"): ["GHSA-lodash"]}
    return {
        "results": [
            {"vulns": [{"id": identifier} for identifier in hits.get((query["package"]["name"], query["version"]), [])]}
            for query in payload["queries"]
        ]
    }


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\nflask>=3.0,<4.0\noldlib==1.0\nreqeusts==1.0.0\n")
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo", "license": "MIT",
        "dependencies": {"lodash": "4.17.15", "left-pad": "1.3.0", "expresss": "1.0.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "app.py").write_text(
        '"""Demo."""\nimport flask\nimport oldlib\n\n\ndef run(a, b, c, d, e, f, g):\n'
        '    unused = 1\n    if a:\n        return flask\n    return None\n    print("never")\n'
    )
    (tmp_path / "index.js").write_text("const _ = require('lodash');\n")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    return tmp_path


@pytest.fixture
def report(repo):
    return scan_repository(repo, {"name": "acme/demo", "provider": "github"}, fetch=fake_fetch, post=fake_post, today=TODAY)


def _rules(report):
    return [finding["rule_id"] for finding in report["findings"]]


def test_license_expressions():
    assert licenses.evaluate("(MIT OR Apache-2.0)").category == licenses.PERMISSIVE
    assert licenses.evaluate("MIT/Apache-2.0").category == licenses.PERMISSIVE
    assert licenses.evaluate("Apache-2.0 AND GPL-2.0-only").category == licenses.STRONG_COPYLEFT
    assert licenses.evaluate("GPL-3.0 OR Commercial").dual_license_trap
    assert licenses.evaluate("SEE LICENSE IN LICENSE").category == licenses.UNKNOWN
    assert licenses.evaluate("UNLICENSED").category == licenses.NON_COMMERCIAL
    assert licenses.conflicts_with_project(licenses.STRONG_COPYLEFT, licenses.PERMISSIVE)
    assert not licenses.conflicts_with_project(licenses.STRONG_COPYLEFT, licenses.STRONG_COPYLEFT)


def test_version_ranges_and_breaking_upgrades():
    assert satisfies(NPM, "^1.2.3", "1.9.0") and not satisfies(NPM, "^1.2.3", "2.0.0")
    assert satisfies(NPM, "~0.2.1", "0.2.9") and not satisfies(NPM, "^0.0.3", "0.0.4")
    assert newest_satisfying(PYPI, ">=2.32,<3.0", ["2.31.0", "2.32.3", "2.33.0rc1", "3.0.0"]) == "2.32.3"
    assert is_breaking_upgrade(NPM, "0.21.4", "0.22.0")
    assert not is_breaking_upgrade(PYPI, "2.10", "2.11.3")


def test_manifests_skip_vendored_directories(repo):
    names = {dependency.name for dependency in discover_dependencies(repo)}
    assert {"jinja2", "flask", "lodash", "jest"} <= names
    assert all("node_modules" not in dependency.manifest for dependency in discover_dependencies(repo))


def test_typosquatting():
    assert typosquat_target(PYPI, "reqeusts").target == "requests"
    assert typosquat_target(NPM, "expresss").target == "express"
    assert typosquat_target(PYPI, "requests") is None
    assert typosquat_target(NPM, "@types/react") is None
    assert damerau_levenshtein("reqeusts", "requests") == 1


def test_reachability(repo):
    index = ReachabilityIndex(repo)
    assert index.status(Dependency("flask", PYPI, "3.1.0")) == IMPORTED
    assert index.status(Dependency("jinja2", PYPI, "2.10")) == NOT_IMPORTED
    assert index.status(Dependency("lodash", NPM, "4.17.15")) == IMPORTED
    assert index.status(Dependency("@types/node", NPM, "1.0.0")) == UNKNOWN


def test_vulnerabilities_are_deduplicated_and_get_minimum_fix(report):
    _assert_jinja_vulnerability(report)
    _assert_lodash_vulnerability(report)


def _assert_jinja_vulnerability(report):
    jinja = [finding for finding in report["findings"] if finding["rule_id"] == "REPO-DEP-001" and finding["evidence"]["package"] == "jinja2"]
    assert len(jinja) == 1
    assert jinja[0]["evidence"]["upgrade_to"] == "2.10.1"
    assert jinja[0]["evidence"]["breaking_upgrade"] is False
    assert jinja[0]["confidence"] == "tentative"
    assert jinja[0]["location"] == "requirements.txt:1"


def _assert_lodash_vulnerability(report):
    lodash = next(finding for finding in report["findings"] if finding["evidence"].get("package") == "lodash" and finding["rule_id"] == "REPO-DEP-001")
    assert lodash["severity"] == "critical" and lodash["confidence"] == "confirmed"
    assert "4.17.19" in lodash["recommendation"]


def test_supply_chain_and_license_findings(report):
    _assert_typosquat_findings(report)
    _assert_license_findings(report)
    _assert_deprecated_package_finding(report)
    assert report["licenses"]["project"] == "MIT"


def _assert_typosquat_findings(report):
    rules = _rules(report)
    squats = {finding["evidence"]["package"]: finding for finding in report["findings"] if finding["rule_id"] == "REPO-SUP-001"}
    assert squats["expresss"]["severity"] == "critical"
    assert squats["reqeusts"]["severity"] == "high"


def _assert_license_findings(report):
    rules = _rules(report)
    assert "REPO-DEP-002" in rules
    assert "REPO-LIC-001" in rules


def _assert_deprecated_package_finding(report):
    assert any(f["rule_id"] == "REPO-DEP-003" and f["evidence"]["package"] == "oldlib" for f in report["findings"])
    flask = next(record for record in report["dependencies"] if record["name"] == "flask")
    assert flask["version"] == "3.1.0" and flask["resolved_from_range"]


def test_quality_metrics(repo):
    quality = analyse_quality(repo)
    rules = {issue.rule_id for issue in quality.issues}
    assert {"REPO-MNT-003", "REPO-MNT-006", "REPO-MNT-007", "REPO-MNT-011"} <= rules
    assert quality.metrics()["docstring_coverage"] is not None


def test_complexity_measures():
    tree = ast.parse(
        "def f(x):\n    if x and x > 1:\n        for i in x:\n            if i:\n                return 1\n"
        "    elif x:\n        return 2\n    return 3\n"
    )
    function = tree.body[0]
    assert cyclomatic_complexity(function) == 6
    assert cognitive_complexity(function) == 8


def test_duplicate_blocks(tmp_path):
    block = "\n".join(f"    total = total + value_{index} * factor_{index}" for index in range(10))
    (tmp_path / "a.py").write_text(f"def a(total):\n{block}\n    return total\n")
    (tmp_path / "b.py").write_text(f"def b(total):\n{block}\n    return total\n")
    quality = analyse_quality(tmp_path)
    assert any(issue.rule_id == "REPO-MNT-008" for issue in quality.issues)
    assert quality.duplicated_lines > 0


def test_health_and_benchmark(report):
    assert grade(95) == "A" and grade(59) == "F"
    assert report["health"]["overall"]["grade"] in "ABCDF"
    assert report["health"]["security"]["score"] < 100
    clean = health_summary([], {"freshness_index": 100}, {"has_readme": True})
    assert clean["overall"]["grade"] == "A" and clean["overall"]["stars"] == 5.0
    ranks = benchmark({"a": 90, "b": 60, "c": 75})
    assert ranks["a"]["percentile"] == 100 and ranks["c"]["delta_from_median"] == 0


def test_sbom_and_sarif(report):
    _assert_cyclonedx(report)
    _assert_spdx(report)
    _assert_sarif(report)


def _assert_cyclonedx(report):
    assert purl(NPM, "@scope/pkg", "1.0.0") == "pkg:npm/%40scope/pkg@1.0.0"
    bom = cyclonedx(report)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert any(component["name"] == "lodash" for component in bom["components"])
    assert bom["vulnerabilities"]


def _assert_spdx(report):
    document = spdx(report)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert len({package["SPDXID"] for package in document["packages"]}) == len(document["packages"])


def _assert_sarif(report):
    sarif = to_sarif(report)
    run = sarif["runs"][0]
    assert run["results"] and all(result["ruleIndex"] < len(run["tool"]["driver"]["rules"]) for result in run["results"])
    assert all(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"])
    assert all(result["level"] != "error" for result in run["results"] if result["ruleId"].startswith("REPO-MNT-"))


def test_pull_request_suggestions(report, repo):
    assert commentable_lines("@@ -1,2 +1,3 @@\n a\n-b\n+c\n+d\n") == {1, 2, 3}
    assert suggested_line("jinja2==2.10", "2.10", "2.10.1") == "jinja2==2.10.1"
    assert suggested_line("jinja2==2.10.5", "2.10", "2.10.1") is None
    comments, body = build_review(report, {"requirements.txt": {1}, "app.py": {6}}, repo)
    suggestion = next(comment for comment in comments if comment.path == "requirements.txt")
    assert "```suggestion\njinja2==2.10.1\n```" in suggestion.body
    assert any(comment.path == "app.py" for comment in comments)
    assert "SecGuard health" in body


def test_cli_writes_outputs(repo, tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    output = tmp_path / "out"
    output.mkdir()
    code = main(["scan", str(repo), "--offline", "--output", str(output / "r.json"),
                 "--sarif", str(output / "s.sarif"), "--cyclonedx", str(output / "c.json"), "--spdx", str(output / "p.json"),
                 "--fail-on", "high"])
    assert code == 1
    for name in ("r.json", "s.sarif", "c.json", "p.json"):
        assert json.loads((output / name).read_text())


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def test_ingest_and_serve_repository_scan(client, report):
    application_id = _ingest_repository_scan(client, report)
    _assert_repository_listing(client)
    _assert_repository_findings(client, application_id)
    _assert_repository_sbom(client, application_id)
    _assert_repository_quality(client, application_id)


def _ingest_repository_scan(client, report):
    response = client.post("/api/repository/scans", json=report)
    assert response.status_code == 201
    return response.get_json()["application_id"]


def _assert_repository_listing(client):
    listed = client.get("/api/applications").get_json()["applications"]
    assert listed[0]["repository"] == "acme/demo" and listed[0]["platform"] == "Repository"
    assert listed[0]["health"]["overall"]["grade"]


def _assert_repository_findings(client, application_id):
    findings = client.get(f"/api/applications/{application_id}/findings").get_json()["findings"]
    assert {finding["platform"] for finding in findings} == {"Repository"}


def _assert_repository_sbom(client, application_id):
    bom = client.get(f"/api/applications/{application_id}/sbom?format=spdx")
    assert bom.status_code == 200 and "attachment" in bom.headers["Content-Disposition"]
    assert client.get(f"/api/applications/{application_id}/sbom?format=xml").status_code == 400


def _assert_repository_quality(client, application_id):
    quality = client.get(f"/api/applications/{application_id}/quality").get_json()
    assert quality["quality"]["findings"]
    assert client.get("/api/portfolio/summary").status_code == 200


def test_ingest_rejects_tampered_reports(client, report):
    assert client.post("/api/repository/scans", json={"schema": "other"}).status_code == 400
    forged = {**report, "findings": [{"rule_id": "REPO-DEP-001", "severity": "critical", "risk": {"score": 0}, "category": "x"}]}
    response = client.post("/api/repository/scans", json=forged)
    assert response.status_code == 201
    stored = client.get(f"/api/applications/{response.get_json()['application_id']}/findings").get_json()["findings"][0]
    assert stored["category"] == "supply-chain" and stored["risk"]["score"] > 0
    assert client.post("/api/repository/scans", json={**report, "repository": {"name": "../../etc"}}).status_code == 400


def test_cli_records_application_name(repo, tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("SECGUARD_APPLICATION_NAME", "Customer Portal")
    output = tmp_path / "named.json"
    main(["scan", str(repo), "--offline", "--output", str(output)])
    assert json.loads(output.read_text())["repository"]["application_name"] == "Customer Portal"
    main(["scan", str(repo), "--offline", "--output", str(output), "--application-name", "Billing"])
    assert json.loads(output.read_text())["repository"]["application_name"] == "Billing"
    with pytest.raises(SystemExit):
        main(["scan", str(repo), "--offline", "--output", str(output), "--application-name", "x" * 81])
