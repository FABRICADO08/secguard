from backend.rules.base import Rule
from backend.rules.generic import (
    api,
    authentication,
    authorization,
    clientside,
    content_security,
    discovery,
    web,
)


def all_generic_rules() -> list[Rule]:
    """Every platform-agnostic rule, in registration order."""

    return [
        *web.rules(),
        *content_security.rules(),
        *clientside.rules(),
        *discovery.rules(),
        *authentication.rules(),
        *authorization.rules(),
        *api.rules(),
    ]


__all__ = [
    "all_generic_rules",
    "api",
    "authentication",
    "authorization",
    "clientside",
    "content_security",
    "discovery",
    "web",
]
