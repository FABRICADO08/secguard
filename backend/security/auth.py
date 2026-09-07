from __future__ import annotations

import hmac
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import jsonify, request

from backend.config import settings

LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1", "localhost"})


def _presented_token() -> str:
    header = request.headers.get("Authorization", "")

    if header.lower().startswith("bearer "):
        return header[7:].strip()

    return request.headers.get("X-API-Key", "").strip()


def request_is_authorized() -> bool:
    """
    Scanning and deletion are privileged: they drive outbound traffic and
    destroy stored results.

    With `SECGUARD_API_TOKEN` set a matching token is required. Without one
    the endpoints stay open to the local UI but refuse remote callers, so an
    unconfigured deployment cannot be driven from the network.
    """

    if settings.API_TOKEN:

        return hmac.compare_digest(
            _presented_token(),
            settings.API_TOKEN,
        )

    return (request.remote_addr or "") in LOOPBACK_ADDRESSES


def require_api_token(view: Callable[..., Any]) -> Callable[..., Any]:

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):

        if not request_is_authorized():

            return jsonify(
                {
                    "success":
                        False,

                    "error":
                        "Unauthorized. Set SECGUARD_API_TOKEN and send it "
                        "as 'Authorization: Bearer <token>' or 'X-API-Key'.",
                }
            ), 401

        return view(*args, **kwargs)

    return wrapper
