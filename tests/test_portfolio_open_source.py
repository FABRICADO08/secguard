from backend.portfolio.open_source import open_source_overview
from backend.repository.scanner import scan_repository


def _dependency(name, version, **extra):
    return {
        "name": name,
        "ecosystem": "npm",
        "version": version,
        "direct": True,
        "scope": "runtime",
        "license_spdx": "MIT",
        "license_category": "permissive",
        "reachability": "imported",
        "freshness": {"latest": "4.17.21", "behind": {"major": 0, "minor": 0, "patch": 6}},
        "vulnerabilities": [],
        **extra,
    }


LODASH_ADVISORY = {"id": "GHSA-lodash", "severity": "CRITICAL", "summary": "Prototype pollution", "minimum_fix": "4.17.19"}


def _ingest(client, tmp_path, name, dependencies, advisories=()):
    root = tmp_path / name.replace("/", "_")
    root.mkdir(exist_ok=True)
    (root / "app.py").write_text("def main():\n    return 1\n")
    report = scan_repository(root, {"name": name, "provider": "github"})
    report["dependencies"] = dependencies
    report["vulnerabilities"] = list(advisories)
    response = client.post("/api/repository/scans", json=report)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["application_id"]


def test_libraries_are_folded_across_systems(client, tmp_path):
    vulnerable = _dependency("lodash", "4.17.15", vulnerabilities=[LODASH_ADVISORY["id"]])
    api = _ingest(client, tmp_path, "acme/api", [vulnerable, _dependency("left-pad", "1.3.0")], [LODASH_ADVISORY])
    web = _ingest(client, tmp_path, "acme/web", [_dependency("Lodash", "4.17.21"), _dependency(
        "gpl-lib", "1.0.0", license_spdx="GPL-3.0-only", license_category="strong-copyleft",
        freshness={"latest": "3.0.0", "behind": {"major": 2}},
    )])

    payload = client.get("/api/portfolio/open-source").get_json()

    assert payload["success"] is True
    _assert_libraries(payload["libraries"], api, web)
    _assert_totals(payload["totals"])
    _assert_systems({system["id"]: system for system in payload["systems"]}, api, web)


def _assert_libraries(listed, api, web):
    libraries = {library["name"].lower(): library for library in listed}
    lodash = libraries["lodash"]
    assert listed[0]["name"] == "lodash"
    assert lodash["systems"] == 2 and lodash["versions"] == ["4.17.15", "4.17.21"]
    assert lodash["severity"] == "critical" and lodash["advisories"][0]["summary"] == "Prototype pollution"
    assert {usage["system_id"]: usage["advisories"] for usage in lodash["usages"]} == {api: ["GHSA-lodash"], web: []}
    _assert_copyleft(libraries["gpl-lib"])


def _assert_copyleft(library):
    assert library["license_risk"] is True and library["major_behind"] == 2
    assert library["license"] == "GPL-3.0-only" and library["systems"] == 1


def _assert_totals(totals):
    assert totals == {
        "systems": 2, "libraries": 3, "usages": 4, "vulnerable": 1, "major_behind": 1, "license_risk": 1,
        "advisories": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        "license_categories": {"permissive": 2, "strong-copyleft": 1},
    }


def _assert_systems(systems, api, web):
    assert systems[api]["vulnerable"] == 1 and systems[api]["severity"] == "critical"
    assert systems[api]["dependencies"] == 2 and systems[api]["direct"] == 2
    assert systems[web]["license_risk"] == 1 and systems[web]["major_behind"] == 1


def test_only_the_latest_scan_of_a_system_counts(client, tmp_path):
    _ingest(client, tmp_path, "acme/api", [_dependency("lodash", "4.17.15", vulnerabilities=[LODASH_ADVISORY])])
    _ingest(client, tmp_path, "acme/api", [_dependency("lodash", "4.17.21")])

    payload = client.get("/api/portfolio/open-source").get_json()

    assert payload["totals"]["systems"] == 1
    assert payload["libraries"][0]["versions"] == ["4.17.21"] and payload["totals"]["vulnerable"] == 0


def test_malformed_dependencies_are_ignored():
    applications = [{"id": "a", "name": "api", "platform": "Repository", "requested_url": "github://acme/api"},
                    {"id": "b", "name": "site", "platform": "Generic", "requested_url": "https://example.test"}]
    stored = {"a": {"repository": {"dependencies": ["x", {"name": ""}, {"name": "ok", "vulnerabilities": "bad",
                                                                       "freshness": {"behind": {"major": True}}}]}}}

    overview = open_source_overview(applications, lambda key: stored.get(key, {}))

    assert [library["name"] for library in overview["libraries"]] == ["ok"]
    assert overview["libraries"][0]["major_behind"] == 0 and overview["libraries"][0]["license_category"] == "unknown"
    assert overview["totals"]["systems"] == 1


def test_open_source_view_is_empty_without_repository_scans(client):
    payload = client.get("/api/portfolio/open-source").get_json()

    assert payload["systems"] == [] and payload["libraries"] == [] and payload["totals"]["libraries"] == 0


def test_pypi_spellings_fold_and_latest_release_follows_the_newest_scan(client, tmp_path):
    older = _dependency("zope.interface", "5.0.0", ecosystem="PyPI", freshness={"latest": "5.0.0", "behind": {}})
    newer = _dependency("zope_interface", "5.0.0", ecosystem="PyPI", freshness={"latest": "6.0.0", "behind": {"major": 1}})
    _ingest(client, tmp_path, "acme/zeta", [older])
    _ingest(client, tmp_path, "acme/alpha", [newer])

    libraries = client.get("/api/portfolio/open-source").get_json()["libraries"]

    assert len(libraries) == 1
    assert libraries[0]["systems"] == 2 and libraries[0]["latest"] == "6.0.0"
