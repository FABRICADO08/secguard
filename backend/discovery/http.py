from __future__ import annotations

from http.cookiejar import Cookie
from typing import Any
from urllib.parse import urljoin

import requests

from backend.config.settings import PROBE_TIMEOUT, USER_AGENT


def build_session() -> requests.Session:
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,"
                      "application/json;q=0.9,*/*;q=0.8",
        }
    )

    return session


def absolute_url(base_url: str, path: str) -> str:
    return urljoin(
        base_url.rstrip("/") + "/",
        path.lstrip("/"),
    )


# Servers spell cookie attributes inconsistently and the cookiejar
# preserves the casing it received, so every variant must be probed.
_HTTP_ONLY_KEYS = ("HttpOnly", "httponly", "HTTPOnly", "Httponly")
_SAME_SITE_KEYS = ("SameSite", "samesite", "Samesite", "sameSite")


def _nonstandard_attr(cookie: Cookie, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if cookie.has_nonstandard_attr(key):
            return cookie.get_nonstandard_attr(key) or ""

    return None


def cookie_to_dict(cookie: Cookie) -> dict[str, Any]:
    """Normalize a cookiejar cookie into a serializable record."""

    return {
        "name": cookie.name,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": bool(cookie.secure),
        "http_only": _nonstandard_attr(cookie, _HTTP_ONLY_KEYS) is not None,
        "same_site": _nonstandard_attr(cookie, _SAME_SITE_KEYS) or "",
        "expires": cookie.expires,
    }


def probe(
    url: str,
    session: requests.Session | None = None,
    timeout: int = PROBE_TIMEOUT,
) -> dict[str, Any]:
    """
    Issue a single GET and summarize the response.

    Never raises: a failed probe is reported with `reachable: False`.
    """

    session = session or build_session()

    result: dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "content_type": "",
        "content_length": 0,
        "final_url": url,
        "body_preview": "",
        "error": "",
    }

    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )

    except requests.RequestException as exc:
        result["error"] = str(exc)

        return result

    body = response.text or ""

    result.update(
        {
            "reachable": True,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "content_length": len(response.content or b""),
            "final_url": response.url,
            "body_preview": body[:512],
        }
    )

    return result
