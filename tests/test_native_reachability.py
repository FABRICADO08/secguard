import pytest

from backend.repository.manifests import Dependency
from backend.repository.reachability import (
    IMPORTED,
    NOT_IMPORTED,
    UNKNOWN,
    ReachabilityIndex,
)
from backend.repository.typosquat import typosquat_target
from backend.repository.versions import CARGO, COCOAPODS, MAVEN, NUGET, PUB, SWIFT

SOURCES = {
    "src/Api/Program.cs": "global using System.Text;\nusing Newtonsoft.Json.Linq;\nusing Serilog;\nusing Amazon.S3.Model;\nusing Amazon.Runtime;\n",
    "src/main/java/App.java": "import com.fasterxml.jackson.databind.ObjectMapper;\nimport com.google.common.collect.Lists;\nimport org.apache.commons.lang3.StringUtils;\nimport org.slf4j.Logger;\nimport org.mockito.Mockito;\n",
    "app/build.gradle.kts": "plugins { id(\"application\") }\n",
    "src/main.rs": "use serde_json::Value;\n\n#[tokio::main]\nasync fn main() { let _ = anyhow::anyhow!(\"x\"); }\n",
    "lib/main.dart": "import 'package:http/http.dart' as http;\nimport 'package:flutter_bloc/flutter_bloc.dart';\n",
    "Sources/App/main.swift": "import Alamofire\n@testable import NIOCore\nimport class Kingfisher.ImageCache\nimport FirebaseAnalytics\nimport OrderedCollections\n",
    "ios/App/AppDelegate.m": "#import <AFNetworking/AFNetworking.h>\n@import FirebaseAnalytics;\n",
}


@pytest.fixture
def index(tmp_path):
    for name, text in SOURCES.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return ReachabilityIndex(tmp_path)


@pytest.mark.parametrize(("name", "ecosystem", "expected"), [
    ("Newtonsoft.Json", NUGET, IMPORTED),
    ("Serilog.Sinks.Console", NUGET, UNKNOWN),
    ("AWSSDK.S3", NUGET, IMPORTED),
    ("AWSSDK.Core", NUGET, IMPORTED),
    ("Swashbuckle.AspNetCore", NUGET, UNKNOWN),
    ("Serilog", NUGET, IMPORTED),
    ("Dapper", NUGET, NOT_IMPORTED),
    ("com.fasterxml.jackson.core:jackson-databind", MAVEN, IMPORTED),
    ("com.google.guava:guava", MAVEN, IMPORTED),
    ("org.yaml:snakeyaml", MAVEN, NOT_IMPORTED),
    ("org.apache.commons:commons-lang3", MAVEN, IMPORTED),
    ("org.apache.commons:commons-text", MAVEN, UNKNOWN),
    ("org.slf4j:slf4j-api", MAVEN, IMPORTED),
    ("org.mockito:mockito-core", MAVEN, IMPORTED),
    ("org.apache.logging.log4j:log4j-api", MAVEN, NOT_IMPORTED),
    ("org.apache.logging.log4j:log4j-core", MAVEN, NOT_IMPORTED),
    ("org.springframework.boot:spring-boot-starter-web", MAVEN, UNKNOWN),
    ("serde-json", CARGO, IMPORTED),
    ("tokio", CARGO, IMPORTED),
    ("anyhow", CARGO, IMPORTED),
    ("regex", CARGO, NOT_IMPORTED),
    ("http", PUB, IMPORTED),
    ("flutter_bloc", PUB, IMPORTED),
    ("dio", PUB, NOT_IMPORTED),
    ("build_runner", PUB, UNKNOWN),
    ("github.com/alamofire/alamofire", SWIFT, IMPORTED),
    ("github.com/apple/swift-nio", SWIFT, IMPORTED),
    ("github.com/onevcat/kingfisher", SWIFT, IMPORTED),
    ("github.com/apple/swift-log", SWIFT, NOT_IMPORTED),
    ("github.com/firebase/firebase-ios-sdk", SWIFT, IMPORTED),
    ("github.com/apple/swift-collections", SWIFT, IMPORTED),
    ("github.com/example/charts-kit", SWIFT, UNKNOWN),
    ("AFNetworking", COCOAPODS, IMPORTED),
    ("Firebase/Analytics", COCOAPODS, IMPORTED),
    ("SnapKit", COCOAPODS, NOT_IMPORTED),
])
def test_native_reachability(index, name, ecosystem, expected):
    assert index.status(Dependency(name, ecosystem, "1.0.0")) == expected


def test_renamed_cargo_dependency_matches_its_import_alias(index):
    renamed = Dependency("serde_json", CARGO, "1.0.0", alias="json")
    assert index.status(renamed) == NOT_IMPORTED
    (index.root / "src" / "lib.rs").write_text("use json::Value;\n", encoding="utf-8")
    assert ReachabilityIndex(index.root).status(renamed) == IMPORTED


def test_unimported_transitive_dependency_is_transitive(index):
    assert index.status(Dependency("regex", CARGO, "1.0.0", direct=False)) == "transitive"


@pytest.mark.parametrize(("ecosystem", "name", "target"), [
    (NUGET, "Newtonsoft.Jsom", "newtonsoft.json"),
    (MAVEN, "com.fasterxml.jackson.core:jackson-databnd", None),
    (MAVEN, "com.fasterxm1.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-databind"),
    (CARGO, "serde_jsno", "serde_json"),
    (PUB, "provder", "provider"),
    (SWIFT, "github.com/alamofre/alamofire", "github.com/alamofire/alamofire"),
    (SWIFT, "github.com/a1amofire/alamofire", "github.com/alamofire/alamofire"),
    (COCOAPODS, "Alamofier", "alamofire"),
])
def test_typosquats_in_newer_ecosystems(ecosystem, name, target):
    signal = typosquat_target(ecosystem, name)
    assert (signal.target if signal else None) == target


@pytest.mark.parametrize(("ecosystem", "name"), [
    (NUGET, "Newtonsoft.Json"),
    (NUGET, "Microsoft.Extensions.Loging"),
    (CARGO, "serde-json"),
    (COCOAPODS, "Firebase/Analytics"),
    (MAVEN, "com.google.guava:guava"),
    (SWIFT, "github.com/alamofire/alamofre"),
])
def test_genuine_or_owner_controlled_names_are_not_typosquats(ecosystem, name):
    assert typosquat_target(ecosystem, name) is None
