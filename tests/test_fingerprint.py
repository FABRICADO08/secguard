import pytest
import requests

from backend.discovery import fingerprint
from backend.discovery.fingerprint import (
    CertificateRejectedError,
    TargetUnreachableError,
    check_http_redirect,
    fetch_application,
    validate_url,
)
from backend.security.targets import BlockedTargetError


class _Response:
    def __init__(self, url, status_code=200, headers=None, text="", history=(), cookies=()):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.history = list(history)
        self.cookies = list(cookies)


class _Session:
    """Records requests and answers or raises as scripted."""

    def __init__(self, responder):
        self.responder = responder
        self.urls = []

    def get(self, url, timeout=None, allow_redirects=True):
        self.urls.append(url)
        outcome = self.responder(url)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


# ------------------------------------------------------------ validate


def test_validate_url_strips_whitespace_and_trailing_slash():
    assert validate_url("  https://example.com/  ") == "https://example.com"


@pytest.mark.parametrize(
    "url, message",
    [
        ("", "Application URL is required."),
        ("ftp://example.com", "URL must start with http:// or https://."),
        ("https://", "The application URL is invalid."),
    ],
)
def test_validate_url_rejects_bad_input(url, message):
    with pytest.raises(ValueError, match=message):
        validate_url(url)


# ------------------------------------------------- plain-http redirect


def test_check_http_redirect_skips_plain_http_targets():
    assert check_http_redirect("http://example.com") == {
        "tested": False,
        "reason": "target is not https",
    }


def test_check_http_redirect_reports_upgrade():
    session = _Session(
        lambda url: _Response("https://example.com/", status_code=200)
    )

    result = check_http_redirect("https://example.com/", session)

    assert result["tested"] is True
    assert result["http_url"] == "http://example.com/"
    assert result["redirects_to_https"] is True
    assert result["status_code"] == 200


def test_check_http_redirect_notes_when_upgrade_is_missing():
    session = _Session(lambda url: _Response(url))

    result = check_http_redirect("https://example.com/", session)

    assert result["redirects_to_https"] is False


def test_check_http_redirect_reports_transport_failures():
    session = _Session(lambda url: requests.ConnectionError("refused"))

    result = check_http_redirect("https://example.com/", session)

    assert result["tested"] is False
    assert "refused" in result["reason"]


# -------------------------------------------------------- error mapping


def test_fetch_maps_timeouts_to_unreachable(monkeypatch):
    monkeypatch.setattr(
        fingerprint, "build_session", lambda: _Session(lambda url: requests.Timeout())
    )

    with pytest.raises(TargetUnreachableError, match="did not respond"):
        fetch_application("https://example.com")


def test_fetch_maps_connection_errors_to_unreachable(monkeypatch):
    monkeypatch.setattr(
        fingerprint,
        "build_session",
        lambda: _Session(lambda url: requests.ConnectionError("refused")),
    )

    with pytest.raises(TargetUnreachableError, match="Could not connect"):
        fetch_application("https://example.com")


def test_fetch_maps_certificate_failures(monkeypatch):
    def responder(url):
        error = requests.exceptions.SSLError("certificate verify failed")
        error.request = type("Req", (), {"url": "https://example.com/"})()
        return error

    monkeypatch.setattr(fingerprint, "build_session", lambda: _Session(responder))

    with pytest.raises(CertificateRejectedError) as captured:
        fetch_application("https://example.com")

    assert captured.value.url == "https://example.com/"
    assert "did not validate" in str(captured.value)


def test_fetch_lets_blocked_targets_through(monkeypatch):
    monkeypatch.setattr(
        fingerprint,
        "build_session",
        lambda: _Session(lambda url: BlockedTargetError("private address")),
    )

    with pytest.raises(BlockedTargetError):
        fetch_application("https://example.com")


def test_fetch_unwraps_blocked_targets_inside_ssl_errors(monkeypatch):
    blocked = BlockedTargetError("private address")
    monkeypatch.setattr(
        fingerprint,
        "build_session",
        lambda: _Session(lambda url: requests.exceptions.SSLError(blocked)),
    )

    with pytest.raises(BlockedTargetError):
        fetch_application("https://example.com")


def test_fetch_unwraps_blocked_targets_inside_connection_errors(monkeypatch):
    blocked = BlockedTargetError("private address")
    monkeypatch.setattr(
        fingerprint,
        "build_session",
        lambda: _Session(lambda url: requests.ConnectionError(blocked)),
    )

    with pytest.raises(BlockedTargetError):
        fetch_application("https://example.com")


# --------------------------------------------------------- happy path


@pytest.fixture
def fetched(monkeypatch):
    hop = _Response(
        "http://example.com/",
        status_code=301,
        headers={"Location": "https://example.com/"},
    )
    final = _Response(
        "https://example.com/",
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "Server": "test-server",
            "X-Powered-By": "unit-test",
        },
        text="<html></html>",
        history=[hop],
    )
    session = _Session(lambda url: final if url.startswith("https") else _Response(url))
    monkeypatch.setattr(fingerprint, "build_session", lambda: session)

    return fetch_application("https://example.com/")


def test_fetch_application_reports_the_final_response(fetched):
    assert fetched["requested_url"] == "https://example.com"
    assert fetched["final_url"] == "https://example.com/"
    assert fetched["status_code"] == 200
    assert fetched["https"] is True


def test_fetch_application_captures_headers_and_body(fetched):
    assert fetched["server"] == "test-server"
    assert fetched["powered_by"] == "unit-test"
    assert fetched["body"] == "<html></html>"
    assert fetched["content_type"] == "text/html"


def test_fetch_application_records_the_redirect_chain(fetched):
    assert fetched["redirect_chain"] == [
        {
            "url": "http://example.com/",
            "status_code": 301,
            "location": "https://example.com/",
        }
    ]
    assert fetched["http_redirect"]["tested"] is True
    assert isinstance(fetched["response_time_ms"], float)
