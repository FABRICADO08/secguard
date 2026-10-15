import subprocess

from backend.repository.code_patterns import pattern_issues
from backend.repository.code_python import python_issues
from backend.repository.code_security import analyse_code_security
from backend.repository.ingest import application_from_report
from backend.repository.sarif import to_sarif
from backend.repository.scanner import scan_repository

AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"


def rules(issues):
    return sorted((issue.rule_id, issue.line) for issue in issues)


def test_python_injection_deserialization_and_transport():
    source = '''import os, pickle, subprocess, yaml, requests
from subprocess import run as sh

def handler(user, cursor, app):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    cursor.execute("SELECT * FROM users WHERE name = %s", (user,))
    os.system("ls " + user)
    sh(user, shell=True)
    subprocess.run(["ls", user])
    eval(user)
    pickle.loads(user)
    yaml.load(user)
    yaml.load(user, Loader=yaml.SafeLoader)
    requests.get(user, verify=False)
    app.run(debug=True)
    eval(user)  # nosec - reviewed
'''
    assert rules(python_issues("app.py", source)) == [
        ("REPO-SEC-001", 5), ("REPO-SEC-002", 7), ("REPO-SEC-002", 8), ("REPO-SEC-003", 10),
        ("REPO-SEC-004", 11), ("REPO-SEC-004", 12), ("REPO-SEC-007", 14), ("REPO-SEC-008", 15),
    ]


def test_django_debug_setting_and_unparsable_files():
    assert rules(python_issues("site/settings.py", "DEBUG = True\n")) == [("REPO-SEC-008", 1)]
    assert python_issues("broken.py", "def (:\n") == []


def test_line_patterns_per_language():
    javascript = (
        "db.query(`SELECT * FROM t WHERE id = ${id}`);\n"
        "db.query('SELECT * FROM t WHERE id = ?', [id]);\n"
        "exec(`git log ${branch}`);\n"
        "/x/.exec(text);\n"
        "eval(payload);\n"
        "// eval(payload);\n"
        "const agent = new https.Agent({ rejectUnauthorized: false });\n"
    )
    assert rules(pattern_issues("a.js", javascript, "JavaScript")) == [
        ("REPO-SEC-001", 1), ("REPO-SEC-002", 3), ("REPO-SEC-003", 5), ("REPO-SEC-007", 7),
    ]
    java = 'stmt.executeQuery("SELECT * FROM t WHERE id = " + id);\nin = new ObjectInputStream(s);\n'
    assert rules(pattern_issues("A.java", java, "Java")) == [("REPO-SEC-001", 1), ("REPO-SEC-004", 2)]
    go = 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))\ncfg := &tls.Config{InsecureSkipVerify: true}\n'
    assert rules(pattern_issues("a.go", go, "Go")) == [("REPO-SEC-001", 1), ("REPO-SEC-007", 2)]
    php = '$r = mysqli_query($c, "SELECT * FROM t WHERE id = $id");\n$o = unserialize($_COOKIE["x"]);\n'
    assert rules(pattern_issues("a.php", php, "PHP")) == [("REPO-SEC-001", 1), ("REPO-SEC-004", 2)]
    csharp = "var f = new BinaryFormatter();\n"
    assert rules(pattern_issues("A.cs", csharp, "C#")) == [("REPO-SEC-004", 1)]


def test_secrets_in_tree_skip_placeholders_and_tests(tmp_path):
    (tmp_path / "config.yml").write_text(f"aws_key: {AWS_KEY}\napi_key: 'your_api_key_here_123'\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text(f'KEY = "{AWS_KEY}"\neval(x)\n')

    issues = analyse_code_security(tmp_path, history=False)

    assert rules(issues) == [("REPO-SEC-005", 1)]
    assert AWS_KEY not in str(issues[0].to_dict())


def _git(root, *arguments):
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


def test_removed_secret_is_found_in_history(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "dev@example.invalid")
    _git(tmp_path, "config", "user.name", "Dev")
    settings = tmp_path / "settings.env"
    settings.write_text(f"AWS={AWS_KEY}\n")
    _git(tmp_path, "add", "settings.env")
    _git(tmp_path, "commit", "-qm", "add config")
    settings.write_text("AWS=${AWS_ACCESS_KEY_ID}\n")
    _git(tmp_path, "commit", "-qam", "use env")

    (issue,) = analyse_code_security(tmp_path)

    assert (issue.rule_id, issue.path, issue.line) == ("REPO-SEC-006", "settings.env", 0)
    assert len(issue.details["commit"]) == 40
    assert analyse_code_security(tmp_path, history=False) == []


def test_scan_reports_code_security_findings_end_to_end(tmp_path):
    (tmp_path / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")

    report = scan_repository(tmp_path, {"name": "acme/portal"})

    (finding,) = [item for item in report["findings"] if item["rule_id"].startswith("REPO-SEC-")]
    assert (finding["rule_id"], finding["severity"], finding["location"]) == ("REPO-SEC-002", "high", "app.py:4")
    assert finding["cwe"] == "CWE-78"
    assert report["health"]["security"]["score"] < 100


def test_code_security_findings_reach_sarif_and_storage(tmp_path):
    (tmp_path / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    report = scan_repository(tmp_path, {"name": "acme/portal"})

    sarif = to_sarif(report)
    rule = next(rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"] if rule["id"] == "REPO-SEC-002")
    assert "argument list" in rule["help"]["text"]
    _, findings = application_from_report(report)
    assert any(item["rule_id"] == "REPO-SEC-002" for item in findings)


def test_constant_only_strings_and_suppressed_debug_are_not_reported():
    source = '''import os

def handler(cursor):
    cursor.execute("SELECT " + "* FROM users")
    os.system("echo " + "hello")
    cursor.execute("SELECT * FROM {}".format("users"))
'''
    assert python_issues("app.py", source) == []
    assert python_issues("site/settings.py", "DEBUG = True  # nosec - local only\n") == []


def test_snippets_never_contain_the_secret():
    (issue,) = python_issues("app.py", f'import os\nos.system("deploy --key {AWS_KEY} " + target)\n')

    assert AWS_KEY not in issue.snippet
    assert "[REDACTED]" in issue.snippet


def _repository_with_removed_secret(root, path):
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "dev@example.invalid")
    _git(root, "config", "user.name", "Dev")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"AWS={AWS_KEY}\n")
    _git(root, "add", path)
    _git(root, "commit", "-qm", "add config")
    return target


def test_history_is_read_when_scanning_a_subdirectory(tmp_path):
    target = _repository_with_removed_secret(tmp_path, "packages/api/settings.env")
    target.write_text("AWS=${AWS_ACCESS_KEY_ID}\n")
    _git(tmp_path, "commit", "-qam", "use env")

    (issue,) = analyse_code_security(tmp_path / "packages" / "api")

    assert (issue.rule_id, issue.path) == ("REPO-SEC-006", "settings.env")


def test_secret_in_an_oversized_file_is_not_reported_as_removed(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.repository.code_security.MAX_SOURCE_BYTES", 10)
    _repository_with_removed_secret(tmp_path, "settings.env")

    assert analyse_code_security(tmp_path) == []
