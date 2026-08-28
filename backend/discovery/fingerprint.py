from __future__ import annotations

from time import perf_counter
from urllib.parse import urlparse

import requests


USER_AGENT = (
    "Application-Security-Platform/0.1 "
    "(authorized-security-discovery)"
)


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


def fetch_application(url: str) -> dict:
    url = validate_url(url)

    started = perf_counter()

    response = requests.get(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,"
                      "application/json;q=0.9,*/*;q=0.8",
        },
        timeout=20,
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
            cookie.name
            for cookie in response.cookies
        ],
        "body": response.text,
    }