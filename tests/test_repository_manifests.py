import json

from backend.repository import manifests
from backend.repository.manifests import (
    discover_dependencies,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pom,
    parse_pyproject,
    parse_requirements,
)


def _by_name(dependencies):
    return {item.name: item for item in dependencies}


# ------------------------------------------------------------------- pip


def test_requirements_skip_comments_options_urls_and_garbage():
    text = (
        "# a comment\n"
        "\n"
        "-r other.txt\n"
        "git+https://example.com/repo.git\n"
        "https://example.com/wheel.whl\n"
        "flask>=3.0  # inline comment\n"
        "django==4.2\n"
        "!!!not-a-package\n"
    )

    found = _by_name(parse_requirements(text, "requirements.txt"))

    assert set(found) == {"flask", "django"}
    assert found["flask"].spec == ">=3.0"
    assert found["flask"].version == ""
    assert found["flask"].scope == "runtime"
    assert (found["django"].version, found["django"].line) == ("4.2", 7)


def test_requirements_dev_files_and_extras():
    found = parse_requirements("requests[security]==2.31.0\n", "requirements-dev.txt")

    assert found[0].name == "requests"
    assert found[0].version == "2.31.0"
    assert found[0].scope == "development"


# ------------------------------------------------------------ pyproject


def test_pyproject_pep621_dependencies_and_optional_groups():
    text = """
[project]
dependencies = ["requests>=2.31", "uvicorn==0.29.0", "!!!garbage"]

[project.optional-dependencies]
test = ["pytest==8.0"]
server = ["watchfiles"]
"""

    found = _by_name(parse_pyproject(text, "pyproject.toml"))

    assert found["requests"].spec == ">=2.31"
    assert found["requests"].scope == "runtime"
    assert found["uvicorn"].version == "0.29.0"
    assert found["pytest"].scope == "development"
    assert found["watchfiles"].scope == "runtime"


def test_pyproject_poetry_sections():
    text = """
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
tomli = {version = "^2.0", python = "<3.11"}

[tool.poetry.dev-dependencies]
pytest = "^8.0"

[tool.poetry.group.main.dependencies]
uvicorn = "==0.29.0"

[tool.poetry.group.lint.dependencies]
ruff = "0.4.0"
"""

    found = _by_name(parse_pyproject(text, "pyproject.toml"))

    assert "python" not in found
    assert found["requests"].spec == "^2.31"
    assert found["requests"].scope == "runtime"
    assert found["tomli"].spec == "^2.0"
    assert found["pytest"].scope == "development"
    assert (found["uvicorn"].version, found["uvicorn"].scope) == ("0.29.0", "runtime")
    assert (found["ruff"].version, found["ruff"].scope) == ("0.4.0", "development")


def test_pyproject_invalid_toml_returns_nothing():
    assert parse_pyproject("not [valid", "pyproject.toml") == []


# ------------------------------------------------------------- lockfiles


def test_poetry_lock_versions_and_categories():
    text = """
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"

[[package]]
version = "0.0.0"
"""

    found = parse_poetry_lock(text, "poetry.lock")
    by_name = _by_name(found)

    assert len(found) == 2
    assert (by_name["requests"].version, by_name["requests"].scope) == ("2.31.0", "runtime")
    assert (by_name["pytest"].version, by_name["pytest"].scope) == ("8.0.0", "development")
    assert all(not item.direct for item in found)


def test_poetry_lock_invalid_toml_returns_nothing():
    assert parse_poetry_lock("[[[", "poetry.lock") == []


def test_pipfile_lock_default_and_develop_sections():
    document = {
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }

    by_name = _by_name(parse_pipfile_lock(json.dumps(document), "Pipfile.lock"))

    assert (by_name["requests"].version, by_name["requests"].scope) == ("2.31.0", "runtime")
    assert (by_name["pytest"].version, by_name["pytest"].scope) == ("8.0.0", "development")


def test_pipfile_lock_invalid_json_returns_nothing():
    assert parse_pipfile_lock("{oops", "Pipfile.lock") == []


# ------------------------------------------------------------------- npm


def test_package_json_scopes_and_exact_versions():
    document = {
        "dependencies": {"react": "^18.2.0", "classnames": "2.5.1"},
        "optionalDependencies": {"fsevents": "~2.3.3"},
        "peerDependencies": {"lodash": "4.17.21"},
        "devDependencies": {"jest": "^29.0.0"},
    }

    found = _by_name(parse_package_json(json.dumps(document), "package.json"))

    assert found["react"].version == ""
    assert found["react"].spec == "^18.2.0"
    assert found["classnames"].version == "2.5.1"
    assert found["fsevents"].scope == "runtime"
    assert found["lodash"].version == "4.17.21"
    assert found["jest"].scope == "development"


def test_package_json_invalid_json_returns_nothing():
    assert parse_package_json("{oops", "package.json") == []


def test_package_lock_v2_packages():
    document = {
        "packages": {
            "": {"name": "root"},
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/@types/react": {"version": "18.2.21", "dev": True},
            "node_modules/a/node_modules/left-pad": {"name": "left-pad", "version": "1.3.0"},
        }
    }

    by_name = _by_name(parse_package_lock(json.dumps(document), "package-lock.json"))

    assert set(by_name) == {"react", "@types/react", "left-pad"}
    assert by_name["react"].version == "18.2.0"
    assert by_name["@types/react"].scope == "development"
    assert by_name["left-pad"].version == "1.3.0"
    assert all(not item.direct for item in by_name.values())


def test_package_lock_v1_nested_dependencies():
    document = {
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}}
        }
    }

    by_name = _by_name(parse_package_lock(json.dumps(document), "npm-shrinkwrap.json"))

    assert (by_name["a"].version, by_name["a"].scope) == ("1.0.0", "runtime")
    assert (by_name["b"].version, by_name["b"].scope) == ("2.0.0", "development")


def test_package_lock_invalid_json_returns_nothing():
    assert parse_package_lock("{oops", "package-lock.json") == []


# -------------------------------------------------------------------- go


def test_go_mod_single_and_block_requires():
    text = """module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4 // indirect
)
"""

    by_name = _by_name(parse_go_mod(text, "go.mod"))

    assert set(by_name) == {
        "github.com/pkg/errors",
        "github.com/gin-gonic/gin",
        "github.com/stretchr/testify",
    }
    assert by_name["github.com/pkg/errors"].version == "v0.9.1"
    assert by_name["github.com/pkg/errors"].direct
    assert by_name["github.com/pkg/errors"].line == 5
    assert by_name["github.com/gin-gonic/gin"].direct
    assert not by_name["github.com/stretchr/testify"].direct
    assert all(item.ecosystem == "Go" for item in by_name.values())


# ----------------------------------------------------------------- maven


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <spring.version>6.1.4</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <artifactId>no-group</artifactId>
    </dependency>
  </dependencies>
</project>
"""


def test_pom_namespaces_properties_and_scopes():
    by_name = _by_name(parse_pom(POM, "pom.xml"))

    assert set(by_name) == {"org.springframework:spring-core", "junit:junit"}
    spring = by_name["org.springframework:spring-core"]
    assert spring.version == "6.1.4"
    assert spring.ecosystem == "Maven"
    assert spring.line == POM.splitlines().index("      <artifactId>spring-core</artifactId>") + 1
    assert by_name["junit:junit"].scope == "development"


def test_pom_without_namespace_and_invalid_xml():
    text = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency></dependencies></project>"

    by_name = _by_name(parse_pom(text, "pom.xml"))

    assert by_name["a:b"].version == "1.0"
    assert parse_pom("<project", "pom.xml") == []


# -------------------------------------------------------------- composer


def test_composer_lock_strips_v_prefix_and_marks_dev():
    document = {
        "packages": [{"name": "monolog/monolog", "version": "v3.5.0"}, {"version": "1.0"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}],
    }

    by_name = _by_name(parse_composer_lock(json.dumps(document), "composer.lock"))

    assert set(by_name) == {"monolog/monolog", "phpunit/phpunit"}
    assert (by_name["monolog/monolog"].version, by_name["monolog/monolog"].scope) == ("3.5.0", "runtime")
    assert by_name["phpunit/phpunit"].scope == "development"
    assert all(item.ecosystem == "Packagist" for item in by_name.values())


def test_composer_lock_invalid_json_returns_nothing():
    assert parse_composer_lock("{oops", "composer.lock") == []


# ------------------------------------------------------------------ ruby


def test_gemfile_lock_specs_section_and_platform_suffixes():
    text = """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3)
    nokogiri (1.16.2-x86_64-linux)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)
"""

    by_name = _by_name(parse_gemfile_lock(text, "Gemfile.lock"))

    assert set(by_name) == {"rails", "nokogiri"}
    assert by_name["rails"].version == "7.1.3"
    assert by_name["nokogiri"].version == "1.16.2"
    assert all(item.ecosystem == "RubyGems" and not item.direct for item in by_name.values())


# ------------------------------------------------------------- discovery


def test_discover_dependencies_merges_manifest_with_lockfile(tmp_path):
    (tmp_path / "requirements.txt").write_text("django\n")
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"django": {"version": "==4.2.11"}}})
    )
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "ghost"\nversion = ""\n')

    by_name = _by_name(discover_dependencies(tmp_path))

    django = by_name["django"]
    assert django.version == "4.2.11"
    assert django.manifest == "requirements.txt"
    assert django.direct
    assert "ghost" not in by_name


def test_discover_dependencies_skips_oversized_manifests(tmp_path, monkeypatch):
    monkeypatch.setattr(manifests, "MAX_MANIFEST_BYTES", 4)
    (tmp_path / "requirements.txt").write_text("django==4.2.11\n")

    assert discover_dependencies(tmp_path) == []
