import pytest

from backend.discovery import scripts
from backend.discovery.libraries import detect_in_source, detect_libraries
from backend.knowledge.advisories import (
    advisories_for,
    end_of_life_for,
    normalize_name,
    parse_version,
    version_lt,
)
from tests.test_generic_rules import make_context, rule_ids, run

# ------------------------------------------------------------------
# Component detection
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "url,name,version",
    [
        ("/static/js/jquery-1.12.4.min.js", "jQuery", "1.12.4"),
        ("/vendor/jquery.ui-1.12.1.js", "jQuery UI", "1.12.1"),
        ("https://cdn.test/ajax/libs/jquery/3.3.1/jquery.min.js", "jQuery", "3.3.1"),
        ("/assets/bootstrap-3.3.7.css.js", "Bootstrap", "3.3.7"),
        ("/js/lodash.4.17.15.js", "Lodash", "4.17.15"),
    ],
)
def test_versions_are_read_from_script_urls(url, name, version):
    detected = detect_libraries([url], "", {})

    assert detected[0]["name"] == name
    assert detected[0]["version"] == version


def test_jquery_ui_is_not_reported_as_jquery():
    detected = detect_libraries(["/static/jquery-ui-1.11.4.min.js"], "", {})

    assert [entry["name"] for entry in detected] == ["jQuery UI"]


@pytest.mark.parametrize(
    "url",
    [
        "/assets/notjquery-1.12.4.js",
        "/assets/react-bootstrap-1.6.0.js",
        "/assets/my-lodash-wrapper-1.0.0.js",
        "/assets/bootstrap.bundle.min.js",
    ],
)
def test_a_filename_that_merely_contains_a_library_name_is_ignored(url):
    assert detect_libraries([url], "", {}) == []


def test_angular_is_not_reported_as_angularjs():
    modern = detect_libraries(["/static/angular-17.0.1.js"], "", {})
    legacy = detect_libraries(["/static/angular-1.8.2.min.js"], "", {})

    assert modern[0]["name"] == "Angular"
    assert legacy[0]["name"] == "AngularJS"


def test_angular_carries_no_angularjs_advisories():
    assert advisories_for("Angular", "17.0.1") == []
    assert end_of_life_for("Angular", "17.0.1") is None

    assert advisories_for("AngularJS", "1.8.2")
    assert end_of_life_for("AngularJS", "1.8.2") is not None


def test_page_banner_supplies_a_version_when_the_filename_does_not():
    detected = detect_libraries(
        ["/static/bundle.js"],
        "<!-- jQuery JavaScript Library v1.7.2 -->",
        {},
    )

    assert detected == [
        {
            "name": "jQuery",
            "version": "1.7.2",
            "source": "page-body",
            "evidence": "jQuery JavaScript Library v1.7.2",
        }
    ]


def test_server_components_are_read_from_headers():
    detected = detect_libraries(
        [],
        "",
        {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
    )

    assert {(entry["name"], entry["version"]) for entry in detected} == {
        ("nginx", "1.18.0"),
        ("PHP", "7.4.3"),
    }


def test_the_same_component_is_only_recorded_once():
    detected = detect_libraries(
        [
            "/static/jquery-3.3.1.min.js",
            "/other/jquery-3.3.1.js",
        ],
        "",
        {},
    )

    assert len(detected) == 1


def test_banners_inside_a_bundle_are_detected_and_merged():
    banners = detect_in_source(
        "/static/app.bundle.js",
        "/*! jQuery JavaScript Library v1.7.2 */ ... /*! Bootstrap v3.1.0 */",
    )

    assert {(entry["name"], entry["version"]) for entry in banners} == {
        ("jQuery", "1.7.2"),
        ("Bootstrap", "3.1.0"),
    }

    merged = detect_libraries(["/static/app.bundle.js"], "", {}, extra=banners)

    assert {entry["name"] for entry in merged} == {"jQuery", "Bootstrap"}
    assert all(entry["source"] == "script-banner" for entry in merged)


def test_a_bundle_banner_does_not_duplicate_the_filename_sighting():
    merged = detect_libraries(
        ["/static/jquery-1.7.2.min.js"],
        "",
        {},
        extra=detect_in_source(
            "/static/jquery-1.7.2.min.js",
            "jQuery JavaScript Library v1.7.2",
        ),
    )

    assert len(merged) == 1
    assert merged[0]["source"] == "script-filename"


def test_script_analysis_reports_the_banners_it_reads(monkeypatch):
    monkeypatch.setattr(scripts, "build_session", lambda: object())
    monkeypatch.setattr(
        scripts,
        "_fetch_script",
        lambda url, session: (200, "/*! jQuery JavaScript Library v1.7.2 */"),
    )

    result = scripts.analyze_scripts(
        ["https://app.test/static/app.bundle.js"],
        "https://app.test",
    )

    assert result["libraries"] == [
        {
            "name": "jQuery",
            "version": "1.7.2",
            "source": "script-banner",
            "evidence": "https://app.test/static/app.bundle.js",
        }
    ]
    assert result["scripts"][0]["libraries"] == result["libraries"]


# ------------------------------------------------------------------
# Advisory matching
# ------------------------------------------------------------------

def test_versions_compare_by_component_not_lexically():
    assert version_lt("1.9.1", "1.10.0")
    assert not version_lt("3.5.0", "3.5")


def test_a_prerelease_of_the_fixed_version_is_treated_as_fixed():
    assert parse_version("3.5.0-rc1") == parse_version("3.5.0")
    assert advisories_for("jQuery", "3.5.0-rc1") == []


def test_only_advisories_covering_the_version_are_returned():
    identifiers = {item.identifier for item in advisories_for("jQuery", "3.4.1")}

    assert identifiers == {"CVE-2020-11023"}


def test_the_fixed_release_clears_every_advisory():
    assert advisories_for("jQuery", "3.5.1") == []


def test_a_branch_specific_advisory_does_not_reach_another_branch():
    # Bootstrap 4.3.1 fixed CVE-2019-8331 on the 4.x branch; the 3.x
    # entry stops at 3.4.1 and must not claim 4.3.1 is affected.
    assert advisories_for("Bootstrap", "4.3.1") == []
    assert advisories_for("Bootstrap", "4.1.0")
    assert advisories_for("Bootstrap", "3.3.7")


def test_names_are_normalised_before_lookup():
    assert normalize_name("jQuery UI") == "jquery-ui"
    assert normalize_name("AngularJS") == "angularjs"
    assert advisories_for("jquery-ui", "1.12.1")


def test_an_unknown_component_yields_nothing():
    assert advisories_for("SomeInternalWidget", "1.0.0") == []
    assert end_of_life_for("SomeInternalWidget", "1.0.0") is None


def test_end_of_life_covers_the_branch_below_the_supported_one():
    assert end_of_life_for("jQuery", "2.2.4") is not None
    assert end_of_life_for("jQuery", "3.6.0") is None


def test_a_component_with_no_supported_branch_is_always_unsupported():
    assert end_of_life_for("Moment", "2.29.4") is not None


def test_a_component_without_a_version_is_never_matched():
    assert advisories_for("jQuery", "") == []
    assert end_of_life_for("jQuery", "") is None


# ------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------

def with_libraries(*entries):
    return make_context(
        attack_surface={
            "libraries": [
                {
                    "name": name,
                    "version": version,
                    "source": "script-filename",
                    "evidence": f"/static/{name.lower()}-{version}.js",
                }
                for name, version in entries
            ]
        }
    )


def test_a_vulnerable_component_is_reported_with_its_advisories():
    findings = run(with_libraries(("jQuery", "1.12.4")))

    vulnerable = [f for f in findings if f["rule_id"] == "GEN-DEP-001"]

    assert len(vulnerable) == 1

    advisories = vulnerable[0]["evidence"]["advisories"]

    assert {item["id"] for item in advisories} == {
        "CVE-2020-11023",
        "CVE-2019-11358",
        "CVE-2015-9251",
    }
    assert all(item["fixed_in"] for item in advisories)


def test_the_worst_advisory_decides_the_severity():
    findings = run(with_libraries(("Lodash", "4.17.11")))

    vulnerable = [f for f in findings if f["rule_id"] == "GEN-DEP-001"]

    assert vulnerable[0]["severity"] == "high"


def test_a_current_component_produces_no_dependency_finding():
    findings = run(with_libraries(("jQuery", "3.7.1")))

    assert "GEN-DEP-001" not in rule_ids(findings)
    assert "GEN-DEP-002" not in rule_ids(findings)


def test_an_unsupported_branch_is_reported_separately():
    findings = run(with_libraries(("AngularJS", "1.8.2")))

    assert {"GEN-DEP-001", "GEN-DEP-002"} <= rule_ids(findings)


def test_each_component_is_reported_once():
    findings = run(
        with_libraries(("jQuery", "1.12.4"), ("Lodash", "4.17.11"))
    )

    vulnerable = [f for f in findings if f["rule_id"] == "GEN-DEP-001"]

    assert len(vulnerable) == 2


def test_a_component_without_a_version_is_skipped():
    context = make_context(
        attack_surface={"libraries": [{"name": "jQuery", "version": ""}]}
    )

    assert "GEN-DEP-001" not in rule_ids(run(context))
