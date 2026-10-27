"""Logging, request IDs and the optional Azure Application Insights exporter."""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import traceback
import uuid
from datetime import UTC, datetime

from flask import g, has_request_context, request

from backend.config import settings

LOG = logging.getLogger("secguard.request")

REQUEST_ID_HEADER = "X-Request-ID"

# Accept a caller's ID only when it is short and plain, so it cannot forge log lines.
_VALID_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")

_QUIET_PATHS = frozenset({"/api/health", "/api/health/ready"})

_HANDLER_NAME = "secguard"


def current_request_id() -> str:
    return getattr(g, "request_id", "") if has_request_context() else ""


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = current_request_id()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger, message, request ID and any extras."""

    EXTRAS = ("method", "path", "status", "duration_ms")

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if getattr(record, "request_id", ""):
            entry["request_id"] = record.request_id
        entry.update({name: getattr(record, name) for name in self.EXTRAS if hasattr(record, name)})
        if record.exc_info:
            entry["exception"] = record.exc_info[0].__name__
            entry["stack"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(entry, default=str)


def _formatter() -> logging.Formatter:
    if settings.LOG_FORMAT == "json":
        return JsonFormatter()
    return logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s")


def configure_logging() -> None:
    """Install SecGuard's root handler once; calling again replaces it."""
    root = logging.getLogger()
    for handler in [handler for handler in root.handlers if handler.get_name() == _HANDLER_NAME]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(_formatter())
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))

    _configure_application_insights()


def _configure_application_insights() -> None:
    if not settings.APPLICATIONINSIGHTS_CONNECTION_STRING:
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
    except ImportError:
        logging.getLogger(__name__).warning(
            "APPLICATIONINSIGHTS_CONNECTION_STRING is set but azure-monitor-opentelemetry is not installed"
        )
        return
    configure_azure_monitor(connection_string=settings.APPLICATIONINSIGHTS_CONNECTION_STRING)


def _start_request() -> None:
    presented = request.headers.get(REQUEST_ID_HEADER, "")
    g.request_id = presented if _VALID_REQUEST_ID.fullmatch(presented) else uuid.uuid4().hex
    g.request_started = time.perf_counter()


def _finish_request(response):
    response.headers[REQUEST_ID_HEADER] = current_request_id()
    duration_ms = round((time.perf_counter() - g.get("request_started", time.perf_counter())) * 1000, 1)
    quiet = request.path in _QUIET_PATHS and response.status_code < 400
    level = logging.DEBUG if quiet else logging.INFO
    LOG.log(
        level,
        "%s %s %s",
        request.method,
        request.path,
        response.status_code,
        extra={"method": request.method, "path": request.path, "status": response.status_code,
               "duration_ms": duration_ms},
    )
    return response


def install(app) -> None:
    """Give every request an ID, return it in X-Request-ID and log one access line."""
    app.before_request(_start_request)
    app.after_request(_finish_request)
