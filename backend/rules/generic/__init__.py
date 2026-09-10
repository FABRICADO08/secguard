from backend.rules.base import Rule
from backend.rules.generic import (
    api,
    authentication,
    authorization,
    clientside,
    content_security,
    transport,
    web,
)


def all_generic_rules() -> list[Rule]:
    """Every platform-agnostic rule, in registration order."""

    return [
        *web.rules(),
        *content_security.rules(),
        *clientside.rules(),
        *authentication.rules(),
        *authorization.rules(),
        *api.rules(),
        *transport.rules(),
    ]


__all__ = [
    "all_generic_rules",
    "api",
    "authentication",
    "authorization",
    "clientside",
    "content_security",
    "transport",
    "web",
]
