import csv
import io
from contextlib import contextmanager

from backend.config import settings
from backend.storage import audit, db

REMOTE = {"REMOTE_ADDR": "203.0.113.7"}


def _entries():
    return audit.recent(100)


def test_state_changing_requests_are_recorded(client):
    response = client.put("/api/teams?token=secret", json={"teams": []})

    (entry,) = _entries()
    assert entry["actor"] == "local"
    assert (entry["method"], entry["path"], entry["status"]) == ("PUT", "/api/teams", response.status_code)
    assert entry["address"] == "127.0.0.1"


def test_reads_are_not_recorded(client):
    client.get("/api/teams")
    client.get("/api/health")

    assert _entries() == []


def test_refused_requests_are_recorded_as_anonymous(client):
    response = client.delete("/api/applications/missing", environ_base=REMOTE)

    (entry,) = _entries()
    assert entry["actor"] == "anonymous" and entry["status"] == response.status_code
    assert entry["address"] == "203.0.113.7"


def test_the_token_holder_is_recorded_as_api_token(client, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "t0ken")

    client.put("/api/teams", json={"teams": []}, headers={"Authorization": "Bearer t0ken"}, environ_base=REMOTE)

    assert _entries()[0]["actor"] == "api-token"


def test_administrators_read_the_log_newest_first(client):
    client.put("/api/teams", json={"teams": []})
    client.put("/api/objectives", json={})

    response = client.get("/api/audit")

    assert response.status_code == 200
    paths = [entry["path"] for entry in response.get_json()["entries"]]
    assert paths == ["/api/objectives", "/api/teams"]
    assert response.get_json()["entries"][0]["time"].endswith("+00:00")


def test_the_limit_is_bounded(client):
    for _ in range(3):
        client.put("/api/teams", json={"teams": []})

    assert len(client.get("/api/audit?limit=2").get_json()["entries"]) == 2
    assert len(client.get("/api/audit?limit=nope").get_json()["entries"]) == 3


def test_other_callers_cannot_read_the_log(client):
    assert client.get("/api/audit", environ_base=REMOTE).status_code == 403
    assert client.get("/api/audit.csv", environ_base=REMOTE).status_code == 403


def test_csv_export_neutralises_formulas(client):
    audit.record({"at": 0.0, "actor": "=HYPERLINK(1)", "method": "POST", "path": "/api/x", "status": 200,
                  "address": "::1"})

    response = client.get("/api/audit.csv")

    assert response.mimetype == "text/csv"
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[0] == ["time", "actor", "method", "path", "status", "address"]
    assert rows[1] == ["1970-01-01T00:00:00+00:00", "'=HYPERLINK(1)", "POST", "/api/x", "200", "::1"]


def test_a_failed_audit_write_does_not_fail_the_request(client, monkeypatch, caplog):
    def broken(entry):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "record", broken)

    response = client.put("/api/teams", json={"teams": []})

    assert response.status_code == 200
    assert "OSError" in caplog.text


def test_corrupt_lines_are_skipped(client):
    audit.record({"at": 1.0, "actor": "local", "method": "PUT", "path": "/api/teams", "status": 200,
                  "address": "::1"})
    with audit.AUDIT_FILE.open("a") as handle:
        handle.write("{not json\n[]\n")

    assert len(_entries()) == 1


def test_postgres_entries_are_inserted_and_read_back(monkeypatch):
    rows = []

    class Cursor:
        def execute(self, sql, params=()):
            if sql.startswith("INSERT INTO audit_log"):
                rows.append(params)
            self._sql = sql

        def fetchall(self):
            return list(reversed(rows))

    @contextmanager
    def connection(init=None):
        assert init is audit._init_schema

        class Connection:
            @contextmanager
            def cursor(self):
                yield Cursor()

        yield Connection()

    monkeypatch.setattr(db, "use_database", lambda: True)
    monkeypatch.setattr(db, "_connection", connection)

    audit.record({"at": 5.0, "actor": "github:octocat", "method": "DELETE", "path": "/api/applications/a",
                  "status": 200, "address": "198.51.100.1"})

    assert rows == [(5.0, "github:octocat", "DELETE", "/api/applications/a", 200, "198.51.100.1")]
    assert audit.recent(10)[0]["actor"] == "github:octocat"


def test_unrouted_paths_are_not_stored(client):
    client.post("/api/token=abc123/nothing-here")

    assert audit.recent(1)[0]["path"] == "(no matching route)"


def test_file_reads_keep_only_the_newest_entries(monkeypatch):
    for index in range(5):
        audit.record({"at": float(index), "actor": "local", "method": "POST", "path": "/api/x", "status": 200,
                      "address": "::1"})

    assert [entry["at"] for entry in audit.recent(2)] == [4.0, 3.0]


def test_an_unwritable_audit_store_is_not_ready(client, monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(audit, "AUDIT_FILE", blocker / "audit" / "audit.jsonl")

    assert client.get("/api/health/ready").status_code == 503


def test_an_audit_file_that_cannot_be_appended_is_not_ready(client):
    audit.AUDIT_FILE.mkdir(parents=True)

    assert client.get("/api/health/ready").status_code == 503
