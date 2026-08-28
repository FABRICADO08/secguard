from __future__ import annotations

from time import perf_counter
from typing import Any
from urllib.parse import urlparse

import requests

from backend.config.settings import FETCH_TIMEOUT, USER_AGENT
from backend.discovery.http import build_session, cookie_to_dict


def validate_url(url: str) -> str:
    url = str(url or "").strip()

    if not url:
        raise ValueError("Application URL is required.")

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "URL must start with http:// or https://."
        )

    if not parsed.netloc:
        raise ValueError("The application URL is invalid.")

    return url.rstrip("/")


def check_http_redirect(
    url: str,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """
    Determine whether the plain-HTTP origin redirects to HTTPS.

    Returns `{"tested": False}` when the check could not be performed.
    """

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {"tested": False, "reason": "target is not https"}

    session = session or build_session()

    http_url = parsed._replace(scheme="http").geturl()

    try:
        response = session.get(
            http_url,
            timeout=FETCH_TIMEOUT,
            allow_redirects=True,
        )

    except requests.RequestException as exc:
        return {"tested": False, "reason": str(exc)}

    return {
        "tested": True,
        "http_url": http_url,
        "final_url": response.url,
        "redirects_to_https": urlparse(response.url).scheme == "https",
        "status_code": response.status_code,
    }


def fetch_application(url: str) -> dict:
    url = validate_url(url)

    session = build_session()

    started = perf_counter()

    response = session.get(
        url,
        timeout=FETCH_TIMEOUT,
        allow_redirects=True,
    )

    elapsed_ms = round(
        (perf_counter() - started) * 1000,
        2,
    )

    parsed = urlparse(response.url)

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "response_time_ms": elapsed_ms,
        "https": parsed.scheme == "https",
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "server": response.headers.get(
            "Server",
            "",
        ),
        "powered_by": response.headers.get(
            "X-Powered-By",
            "",
        ),
        "headers": {
            key: value
            for key, value in response.headers.items()
        },
        "cookies": [
            cookie_to_dict(cookie)
            for cookie in response.cookies
        ],
        "redirect_chain": [
            {
                "url": step.url,
                "status_code": step.status_code,
                "location": step.headers.get("Location", ""),
            }
            for step in response.history
        ],
        "http_redirect": check_http_redirect(
            response.url,
            session,
        ),
        "body": response.text,
    }


__all__ = [
    "USER_AGENT",
    "check_http_redirect",
    "fetch_application",
    "validate_url",
]
