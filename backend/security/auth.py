from __future__ import annotations

import hmac
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import g, jsonify, request

from backend.config import settings
from backend.security import api_keys

SCAN = "scan"

ADMIN = "admin"

LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1", "localhost"})

FORWARDING_HEADERS = (
    "X-Forwarded-For",
    "X-Real-IP",
    "Forwarded",
)


def _presented_token() -> str:
    header = request.headers.get("Authorization", "")

    if header.lower().startswith("bearer "):
        return header[7:].strip()

    return request.headers.get("X-API-Key", "").strip()


def presented_key() -> dict[str, Any] | None:
    """The active API key presented with this request, if any."""
    if "api_key" not in g:
        token = _presented_token()
        g.api_key = api_keys.lookup(token) if token.startswith(api_keys.PREFIX) else None
    return g.api_key


def request_is_authorized(scope: str = ADMIN) -> bool:
    """
    Scanning and deletion are privileged: they drive outbound traffic and
    destroy stored results.

    With `SECGUARD_API_TOKEN` set a matching token is required. Without one
    the endpoints stay open to the local UI but refuse remote callers, so an
    unconfigured deployment cannot be driven from the network.

    A loopback peer only proves locality for a direct connection: behind a
    reverse proxy every forwarded request looks local, so a proxied request
    is refused and the deployment has to configure a token.
    """

    if _presented_token().startswith(api_keys.PREFIX):
        key = presented_key()
        return key is not None and (scope in key["scopes"] or ADMIN in key["scopes"])

    if settings.API_TOKEN:

        return hmac.compare_digest(
            _presented_token(),
            settings.API_TOKEN,
        )

    if any(header in request.headers for header in FORWARDING_HEADERS):
        return False

    return (request.remote_addr or "") in LOOPBACK_ADDRESSES


def require_scope(scope: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Refuse callers without the master token, local access or an API key holding ``scope``."""
    return lambda view: _guard(view, scope)


def require_api_token(view: Callable[..., Any]) -> Callable[..., Any]:
    return _guard(view, ADMIN)


def _guard(view: Callable[..., Any], scope: str) -> Callable[..., Any]:

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):

        if not request_is_authorized(scope):

            return jsonify(
                {
                    "success":
                        False,

                    "error":
                        "Unauthorized. Send SECGUARD_API_TOKEN or an API key with the "
                        f"'{scope}' scope as 'Authorization: Bearer <token>' or 'X-API-Key'.",
                }
            ), 401

        return view(*args, **kwargs)

    return wrapper
