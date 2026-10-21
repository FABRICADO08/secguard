import re
import smtplib
from datetime import datetime, timedelta, timezone

import pytest

from backend.config import settings
from backend.notifications import alerts, channels
from backend.notifications.channels import Message
from backend.reports.__main__ import main as reports_main
from backend.reports.digest import digest_message, digest_rows
from backend.reports.pdf import Document
from backend.repository.scanner import scan_repository
from backend.storage.scans import load_application, save_application
from tests import test_github_auth as auth_tests

github = auth_tests.github
client = auth_tests.client

VULNERABLE = "def handler(user, cursor):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{user}'\")\n"


@pytest.fixture(autouse=True)
def no_channels(monkeypatch):
    for name in ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL", "SMTP_HOST", "PUBLIC_URL"):
        monkeypatch.setattr(settings, name, "")
    monkeypatch.setattr(settings, "ALERT_EMAILS", ())
    monkeypatch.setattr(settings, "ALERT_MIN_SEVERITY", "critical")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")


def ingest(client, tmp_path, name, source, folder):
    root = tmp_path / folder
    root.mkdir()
    (root / "app.py").write_text(source)
    response = client.post("/api/repository/scans", json=scan_repository(root, {"name": name}))
    assert response.status_code == 201, response.get_json()
    return response.get_json()["application_id"]


def test_pdf_is_well_formed_and_paginates():
    document = Document("Report (draft)")
    document.heading("Title \\ (one) – ✓")
    document.table(["A", "B"], [[f"row {index}", "x" * 300] for index in range(80)], [0.5, 0.5])
    content = document.render()
    assert content.startswith(b"%PDF-1.4") and content.endswith(b"%%EOF\n")
    assert b"/Count 2" in content
    assert b"(Title \\\\ \\(one\\) \x96 ?)" in content
    xref = int(re.search(rb"startxref\n(\d+)", content).group(1))
    offsets = re.findall(rb"(\d{10}) 00000 n", content[xref:])
    for number, offset in enumerate(offsets, start=1):
        assert content[int(offset):].startswith(f"{number} 0 obj".encode())


def test_application_and_portfolio_pdf_downloads(client, tmp_path):
    application_id = ingest(client, tmp_path, "acme/api", VULNERABLE, "api")
    client.put("/api/repositories/acme/api/name", json={"name": "Customer Portal"})
    response = client.get(f"/api/applications/{application_id}/report.pdf")
    assert response.status_code == 200 and response.mimetype == "application/pdf"
    assert 'filename="Customer_Portal-secguard-report.pdf"' in response.headers["Content-Disposition"]
    assert b"(Customer Portal)" in response.data and b"SQL injection" in response.data
    assert client.get("/api/applications/missing/report.pdf").status_code == 404
    portfolio = client.get("/api/reports/portfolio.pdf")
    assert portfolio.status_code == 200 and b"(Customer Portal)" in portfolio.data


def test_pdf_reports_follow_github_access(client, github, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "client")
    application_id = auth_tests.ingest(client, tmp_path, "octo/hidden")
    assert client.get("/api/reports/portfolio.pdf").status_code == 401
    assert client.get(f"/api/applications/{application_id}/report.pdf").status_code == 404
    auth_tests.sign_in(client)
    assert client.get("/api/reports/portfolio.pdf").status_code == 200
    assert client.get(f"/api/applications/{application_id}/report.pdf").status_code == 404


def test_scan_adding_a_finding_sends_an_alert(client, tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "_dispatch", sent.append)
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setattr(settings, "PUBLIC_URL", "https://secguard.example")
    monkeypatch.setattr(settings, "ALERT_MIN_SEVERITY", "high")
    ingest(client, tmp_path, "acme/api", "def main():\n    return 1\n", "clean")
    assert sent == []
    application_id = ingest(client, tmp_path, "acme/api", VULNERABLE, "vulnerable")
    assert len(sent) == 1
    assert sent[0].title == "SecGuard: new high or worse finding in api"
    assert "since the previous scan" in sent[0].lines[0] and "SQL injection" in sent[0].lines[1]
    assert sent[0].link.endswith(f"application={application_id}")
    ingest(client, tmp_path, "acme/api", VULNERABLE, "unchanged")
    assert len(sent) == 1


def test_no_alert_below_the_threshold_or_without_channels(client, tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "_dispatch", sent.append)
    ingest(client, tmp_path, "acme/api", VULNERABLE, "unconfigured")
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    ingest(client, tmp_path, "acme/web", VULNERABLE, "critical-only")
    assert sent == []
    monkeypatch.setattr(settings, "ALERT_MIN_SEVERITY", "bogus")
    assert alerts.threshold() == "critical"


def test_first_scan_alert_lists_findings_and_caps_the_list():
    findings = [{"rule_id": "R", "severity": "critical", "title": f"T{index}", "location": f"a{index}.py:1"} for index in range(12)]
    message = alerts.new_findings_message("Portal", "id", None, findings)
    assert "12 new critical findings in its first scan" in message.lines[0]
    assert message.lines[-1] == "...and 2 more." and message.link == ""


class FakeResponse:
    def raise_for_status(self):
        return None


def test_channels_post_slack_and_teams_and_refuse_plain_http(monkeypatch):
    posts = []
    monkeypatch.setattr(channels.requests, "post", lambda url, **kwargs: posts.append((url, kwargs)) or FakeResponse())
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setattr(settings, "TEAMS_WEBHOOK_URL", "http://teams.test/y")
    results = channels.send(Message("Title", ["line"], "https://secguard.example/a"))
    assert results == {"slack": "sent", "teams": "failed (ValueError)"}
    assert posts[0][1]["json"]["text"] == "*Title*\nline\n<https://secguard.example/a|Open in SecGuard>"
    assert posts[0][1]["allow_redirects"] is False and posts[0][1]["timeout"] == channels.TIMEOUT
    monkeypatch.setattr(settings, "TEAMS_WEBHOOK_URL", "https://teams.test/y")
    channels.send(Message("Title", ["line"]))
    card = posts[-1][1]["json"]["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["text"] == "Title"


def test_email_channel_uses_starttls_and_login(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            events.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            events.append(("starttls",))

        def login(self, user, password):
            events.append(("login", user))

        def send_message(self, email):
            events.append(("send", email["To"], email["Subject"]))

    monkeypatch.setattr(channels.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "bot")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "pw")
    monkeypatch.setattr(settings, "SMTP_FROM", "bot@test")
    monkeypatch.setattr(settings, "ALERT_EMAILS", ("a@test", "b@test"))
    assert channels.send(Message("Subject", ["body"])) == {"email": "sent"}
    assert events == [("connect", "smtp.test", 587), ("starttls",), ("login", "bot"), ("send", "a@test, b@test", "Subject")]

    def refuse(*args, **kwargs):
        raise smtplib.SMTPConnectError(421, "busy")

    monkeypatch.setattr(channels.smtplib, "SMTP", refuse)
    assert channels.send(Message("Subject")) == {"email": "failed (SMTPConnectError)"}


def test_alert_and_digest_endpoints_are_admin_only(client, tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("backend.route_reports.send", lambda message: sent.append(message) or {"slack": "sent"})
    assert client.post("/api/alerts/test").status_code == 409
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    data = client.get("/api/alerts").get_json()
    assert data["channels"] == {"slack": True, "teams": False, "email": False} and data["can_edit"] is True
    assert client.post("/api/alerts/test").get_json() == {"success": True, "results": {"slack": "sent"}}
    ingest(client, tmp_path, "acme/api", VULNERABLE, "api")
    assert client.post("/api/reports/digest").status_code == 200
    assert sent[-1].title == "SecGuard weekly digest" and any(line.startswith("- api:") for line in sent[-1].lines)
    monkeypatch.setattr(settings, "API_TOKEN", "token")
    assert client.post("/api/alerts/test").status_code == 403
    assert client.post("/api/reports/digest").status_code == 403
    assert client.get("/api/alerts").get_json()["can_edit"] is False


def test_digest_counts_findings_added_this_week(client, tmp_path):
    old_id = ingest(client, tmp_path, "acme/api", "def main():\n    return 1\n", "old")
    record = load_application(old_id)
    record["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
    save_application(record)
    ingest(client, tmp_path, "acme/api", VULNERABLE, "new")
    ingest(client, tmp_path, "acme/web", VULNERABLE, "web")
    rows = {row["name"]: row for row in digest_rows()}
    assert rows["api"]["new_high"] == 1 and rows["api"]["new_critical"] == 0
    assert rows["web"]["new_high"] == 1
    message = digest_message(list(rows.values()))
    assert "new this week: 0 critical, 2 high" in message.lines[1]
    assert digest_message([]).lines[-1] == "No applications have been scanned yet."


def test_digest_cli_dry_run_and_unconfigured(client, capsys):
    assert reports_main(["digest", "--dry-run"]) == 0
    assert "SecGuard weekly digest" in capsys.readouterr().out
    assert reports_main(["digest"]) == 2


def test_digest_without_a_scan_inside_or_before_the_week(client, tmp_path):
    application_id = ingest(client, tmp_path, "acme/api", VULNERABLE, "api")
    record = load_application(application_id)
    record["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
    save_application(record)
    assert digest_rows()[0]["new_high"] == 0


def test_failed_delivery_returns_502(client, monkeypatch):
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setattr("backend.route_reports.send", lambda message: {"slack": "failed (ConnectionError)"})
    response = client.post("/api/reports/digest")
    assert response.status_code == 502 and response.get_json()["success"] is False
