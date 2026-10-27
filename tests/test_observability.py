import json
import logging
import sys
import types

from backend.config import observability, settings


def test_every_response_gets_a_request_id(client):
    first = client.get("/api/health").headers["X-Request-ID"]
    second = client.get("/api/health").headers["X-Request-ID"]

    assert len(first) == 32 and first != second


def test_a_plain_caller_id_is_kept_and_a_forged_one_replaced(client):
    assert client.get("/api/health", headers={"X-Request-ID": "trace-42"}).headers["X-Request-ID"] == "trace-42"

    forged = client.get("/api/health", headers={"X-Request-ID": "bad id; level=ERROR"}).headers["X-Request-ID"]
    assert forged != "bad id; level=ERROR" and len(forged) == 32


def test_each_request_logs_one_access_line(client, caplog):
    caplog.set_level(logging.INFO, logger="secguard.request")

    response = client.get("/api/teams", headers={"X-Request-ID": "abc"})

    (record,) = [record for record in caplog.records if record.name == "secguard.request"]
    assert (record.method, record.path, record.status) == ("GET", "/api/teams", response.status_code)
    assert record.duration_ms >= 0


def test_health_checks_are_quiet(client, caplog):
    caplog.set_level(logging.INFO, logger="secguard.request")

    client.get("/api/health/ready")

    assert not [record for record in caplog.records if record.name == "secguard.request"]


def test_json_lines_carry_the_request_id_and_exception(client):
    from backend.app import app

    formatter = observability.JsonFormatter()
    with app.test_request_context("/"):
        observability._start_request()
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.LogRecord("secguard.test", logging.ERROR, __file__, 1, "failed %s", ("x",),
                                       sys.exc_info())
        observability.RequestIdFilter().filter(record)
        entry = json.loads(formatter.format(record))

    assert entry["message"] == "failed x" and entry["level"] == "ERROR"
    assert entry["request_id"] == record.request_id and len(entry["request_id"]) == 32
    assert entry["exception"] == "ValueError" and "boom" in entry["stack"]


def test_configuring_twice_keeps_one_handler(monkeypatch):
    monkeypatch.setattr(settings, "LOG_FORMAT", "json")

    observability.configure_logging()
    observability.configure_logging()

    ours = [handler for handler in logging.getLogger().handlers if handler.get_name() == "secguard"]
    assert len(ours) == 1 and isinstance(ours[0].formatter, observability.JsonFormatter)


def test_application_insights_is_configured_when_available(monkeypatch):
    calls = []
    module = types.ModuleType("azure.monitor.opentelemetry")
    module.configure_azure_monitor = lambda **kwargs: calls.append(kwargs)
    monkeypatch.setitem(sys.modules, "azure.monitor.opentelemetry", module)
    monkeypatch.setattr(settings, "APPLICATIONINSIGHTS_CONNECTION_STRING", "InstrumentationKey=k")

    observability._configure_application_insights()

    assert calls == [{"connection_string": "InstrumentationKey=k"}]


def test_a_missing_exporter_only_warns(monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "azure.monitor.opentelemetry", None)
    monkeypatch.setattr(settings, "APPLICATIONINSIGHTS_CONNECTION_STRING", "InstrumentationKey=k")

    observability._configure_application_insights()

    assert "azure-monitor-opentelemetry is not installed" in caplog.text
