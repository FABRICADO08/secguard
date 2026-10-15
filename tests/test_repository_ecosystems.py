import json

from backend.repository.manifests import discover_dependencies
from backend.repository.registry import package_info
from backend.repository.sbom import purl
from backend.repository.scanner import scan_repository
from backend.repository.versions import newest_satisfying

FILES = {
    "api/Api.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog">
      <Version>[2.10.0]</Version>
    </PackageReference>
    <PackageReference Include="Dapper" />
  </ItemGroup>
</Project>
""",
    "Directory.Packages.props": """<Project>
  <ItemGroup><PackageVersion Include="Dapper" Version="2.0.123" /></ItemGroup>
</Project>
""",
    "legacy/packages.config": """<?xml version="1.0"?>
<packages>
  <package id="NUnit" version="3.13.0" developmentDependency="true" />
</packages>
""",
    "android/app/build.gradle": """dependencies {
    implementation 'com.squareup.okhttp3:okhttp:4.9.0'
    testImplementation("junit:junit:4.13.2")
    implementation group: 'com.google.code.gson', name: 'gson', version: '2.8.5'
    implementation "org.example:dynamic:$exampleVersion"
    implementation(libs.retrofit)
    implementation libs.bundles.json
    implementation libs.missing
}
""",
    "gradle/libs.versions.toml": """[versions]
retrofit = "2.9.0"

[libraries]
retrofit = { module = "com.squareup.retrofit2:retrofit", version.ref = "retrofit" }
guava = "com.google.guava:guava:31.0-jre"
moshi-core = "com.squareup.moshi:moshi:1.15.0"
unused = "org.unused:lib:1.0.0"

[bundles]
json = ["moshi-core", "guava"]
""",
    "core/Cargo.toml": """[package]
name = "core"

[dependencies]
serde = "1.0"
time = { version = "=0.1.43" }
local = { path = "../local" }

[dev-dependencies]
proptest = "1"
""",
    "core/Cargo.lock": """[[package]]
name = "core"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "proptest"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
""",
    "mobile/pubspec.yaml": """name: mobile
dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.0
  dio:
    version: 4.0.0
  shared: # local package
    path: ../shared
dev_dependencies:
  mockito: 5.0.0
flutter:
  uses-material-design: true
""",
    "mobile/pubspec.lock": """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dartlang.org"
    source: hosted
    version: "0.13.3"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=2.12.0 <3.0.0"
""",
    "ios/Package.swift": """let package = Package(
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
        .package(url: "https://github.com/vapor/vapor.git", exact: "4.50.0"),
        .package(url: "https://github.com/acme/edge.git", branch: "main"),
    ]
)
""",
    "ios/Package.resolved": json.dumps({"pins": [
        {"identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git",
         "state": {"revision": "abc", "version": "2.29.0"}},
    ], "version": 2}),
    "ios/Podfile": "target 'App' do\n  pod 'Alamofire', '~> 5.4'\n  pod 'Firebase/Analytics'\nend\n",
    "ios/Podfile.lock": "PODS:\n  - Alamofire (5.4.3)\n  - Firebase/Analytics (8.0.0):\n    - Firebase/Core\n  - Firebase/Core (8.0.0)\n\nDEPENDENCIES:\n  - Alamofire (~> 5.4)\n",
}


def _repository(tmp_path):
    for name, text in FILES.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return tmp_path


def _found(tmp_path):
    return {(item.ecosystem, item.name): item for item in discover_dependencies(_repository(tmp_path))}


def test_dotnet_references_borrow_central_versions(tmp_path):
    found = _found(tmp_path)

    assert found[("NuGet", "Newtonsoft.Json")].version == "12.0.1"
    assert found[("NuGet", "Newtonsoft.Json")].line == 3
    assert found[("NuGet", "Serilog")].version == "2.10.0"
    assert found[("NuGet", "Dapper")].version == "2.0.123"
    assert found[("NuGet", "Dapper")].manifest == "api/Api.csproj"
    assert found[("NuGet", "NUnit")].scope == "development"


def test_gradle_scripts(tmp_path):
    found = _found(tmp_path)

    assert found[("Maven", "com.squareup.okhttp3:okhttp")].version == "4.9.0"
    assert found[("Maven", "junit:junit")].scope == "development"
    assert found[("Maven", "com.google.code.gson:gson")].version == "2.8.5"
    assert found[("Maven", "org.example:dynamic")].version == ""


def test_gradle_version_catalog_references(tmp_path):
    found = _found(tmp_path)

    assert found[("Maven", "com.squareup.retrofit2:retrofit")].version == "2.9.0"
    assert found[("Maven", "com.squareup.retrofit2:retrofit")].manifest == "android/app/build.gradle"
    assert found[("Maven", "com.google.guava:guava")].version == "31.0-jre"
    assert found[("Maven", "com.squareup.moshi:moshi")].version == "1.15.0"
    assert ("Maven", "org.unused:lib") not in found
    assert not [key for key in found if key[1].startswith("libs.")]


def test_cargo_ranges_take_the_locked_version(tmp_path):
    found = _found(tmp_path)

    assert found[("crates.io", "serde")].version == "1.0.150"
    assert found[("crates.io", "serde")].direct
    assert found[("crates.io", "time")].version == "0.1.43"
    assert found[("crates.io", "proptest")].scope == "development"
    assert ("crates.io", "local") not in found
    assert ("crates.io", "core") not in found


def test_pub_skips_sdk_and_path_packages(tmp_path):
    found = _found(tmp_path)

    assert found[("Pub", "http")].version == "0.13.3"
    assert found[("Pub", "http")].manifest == "mobile/pubspec.yaml"
    assert found[("Pub", "dio")].version == "4.0.0"
    assert found[("Pub", "mockito")].scope == "development"
    assert ("Pub", "flutter") not in found
    assert ("Pub", "shared") not in found


def test_swift_and_cocoapods(tmp_path):
    found = _found(tmp_path)

    assert found[("SwiftURL", "github.com/apple/swift-nio")].version == "2.29.0"
    assert found[("SwiftURL", "github.com/vapor/vapor")].version == "4.50.0"
    assert ("SwiftURL", "github.com/acme/edge") not in found
    assert found[("CocoaPods", "Alamofire")].version == "5.4.3"
    assert found[("CocoaPods", "Firebase")].version == "8.0.0"


def test_purls_for_new_ecosystems():
    assert purl("NuGet", "Newtonsoft.Json", "12.0.1") == "pkg:nuget/newtonsoft.json@12.0.1"
    assert purl("crates.io", "serde", "1.0.150") == "pkg:cargo/serde@1.0.150"
    assert purl("Pub", "http", "0.13.3") == "pkg:pub/http@0.13.3"
    assert purl("SwiftURL", "github.com/apple/swift-nio", "2.29.0") == "pkg:swift/github.com/apple/swift-nio@2.29.0"
    assert purl("CocoaPods", "Alamofire", "5.4.3") == "pkg:cocoapods/Alamofire@5.4.3"


REGISTRY = {
    "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json": {"versions": ["12.0.1", "13.0.3", "14.0.0-beta1"]},
    "https://crates.io/api/v1/crates/serde": {
        "crate": {"max_stable_version": "1.0.200", "created_at": "2014-12-05T00:00:00Z",
                  "repository": "https://github.com/serde-rs/serde"},
        "versions": [{"num": "1.0.200", "license": "MIT OR Apache-2.0", "created_at": "2024-05-01T00:00:00Z"}],
    },
    "https://pub.dev/api/packages/http": {
        "isDiscontinued": True,
        "latest": {"version": "1.2.0", "published": "2024-01-01T00:00:00Z",
                   "pubspec": {"repository": "https://github.com/dart-lang/http"}},
        "versions": [{"version": "0.13.3", "published": "2021-05-01T00:00:00Z"}],
    },
}


def test_registry_lookups_for_new_ecosystems():
    nuget = package_info("NuGet", "Newtonsoft.Json", REGISTRY.get)
    crate = package_info("crates.io", "serde", REGISTRY.get)
    pub = package_info("Pub", "http", REGISTRY.get)

    assert nuget.latest == "13.0.3"
    assert (crate.latest, crate.license, crate.repository) == ("1.0.200", "MIT OR Apache-2.0", "serde-rs/serde")
    assert pub.latest == "1.2.0" and pub.deprecated and pub.repository == "dart-lang/http"
    assert package_info("crates.io", "missing", REGISTRY.get) is None


ADVISORY = {
    "id": "GHSA-newtonsoft",
    "summary": "Improper handling of exceptional conditions",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "Newtonsoft.Json", "ecosystem": "NuGet"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}]}],
}


def test_nuget_advisories_reach_the_report(tmp_path):
    queried = []

    def post(_url, payload):
        queried.extend(query["package"]["ecosystem"] for query in payload["queries"])
        return {"results": [
            {"vulns": [{"id": "GHSA-newtonsoft"}] if query["package"]["name"] == "Newtonsoft.Json" else []}
            for query in payload["queries"]
        ]}

    def fetch(url):
        return ADVISORY if url.endswith("/GHSA-newtonsoft") else REGISTRY.get(url)

    report = scan_repository(_repository(tmp_path), fetch=fetch, post=post)

    assert {"NuGet", "Maven", "crates.io", "Pub", "SwiftURL", "CocoaPods"} <= set(queried)
    finding = next(item for item in report["findings"] if "GHSA-newtonsoft" in json.dumps(item))
    assert finding["location"] == "api/Api.csproj:3"
    assert "13.0.1" in json.dumps(finding)


def _discover(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return discover_dependencies(tmp_path)


def test_nuget_references_use_the_nearest_central_props(tmp_path):
    props = '<Project><ItemGroup><PackageVersion Include="Foo" Version="{}" />{}</ItemGroup></Project>'
    found = _discover(tmp_path, {
        "service-a/Directory.Packages.props": props.format("1.0.0", ""),
        "service-b/Directory.Packages.props": props.format("2.0.0", '<PackageVersion Include="Unused" Version="1.0.0" />'),
        "service-b/src/Service.csproj": '<Project><ItemGroup><PackageReference Include="Foo" /></ItemGroup></Project>',
    })

    assert [(item.name, item.version, item.manifest, item.direct) for item in found] == [
        ("Foo", "2.0.0", "service-b/src/Service.csproj", True)
    ]


def test_cargo_workspace_definitions_and_non_registry_sources(tmp_path):
    found = _discover(tmp_path, {
        "Cargo.toml": """[workspace.dependencies]
serde = "=1.0.100"
renamed = { package = "real-crate", version = "=2.0.0" }
unused = "=3.0.0"
""",
        "member/Cargo.toml": """[dependencies]
serde = { workspace = true }
renamed = { workspace = true }
widget = { git = "https://example.com/fork", version = "1.2.3" }
private = { version = "1.0", registry = "internal" }
""",
        "Cargo.lock": """[[package]]
name = "weird"
version = "1.0.0"
source = ["registry+https://github.com/rust-lang/crates.io-index"]
""",
    })

    assert {(item.name, item.version, item.manifest) for item in found} == {
        ("serde", "1.0.100", "member/Cargo.toml"),
        ("real-crate", "2.0.0", "member/Cargo.toml"),
    }


def test_pub_packages_from_private_hosts_are_skipped(tmp_path):
    found = _discover(tmp_path, {
        "pubspec.yaml": "name: app\ndependencies:\n  private_pkg:\n    hosted: https://packages.example.org\n    version: 1.0.0\n",
        "pubspec.lock": """packages:
  http:
    dependency: transitive
    description:
      name: http
      url: "https://packages.example.org"
    source: hosted
    version: "1.0.0"
  path:
    dependency: transitive
    description:
      name: path
      url: "https://pub.dev"
    source: hosted
    version: "1.9.0"
""",
    })

    assert [(item.name, item.version) for item in found] == [("path", "1.9.0")]


def test_unlocked_native_ranges_resolve_to_the_newest_allowed_release():
    assert newest_satisfying("crates.io", "1", ["1.0.0", "1.9.0", "2.0.0"]) == "1.9.0"
    assert newest_satisfying("Pub", "^0.13.0", ["0.13.3", "0.13.6", "1.0.0"]) == "0.13.6"
    assert newest_satisfying("NuGet", "[1.0,2.0)", ["1.0.0", "1.5.0", "2.0.0"]) == "1.5.0"
    assert newest_satisfying("NuGet", "1.0", ["0.9.0", "1.5.0", "3.0.0-beta"]) == "1.5.0"
