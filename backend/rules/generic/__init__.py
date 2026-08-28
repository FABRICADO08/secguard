from backend.rules.base import Rule
from backend.rules.generic import api, authentication, authorization, web


def all_generic_rules() -> list[Rule]:
    """Every platform-agnostic rule, in registration order."""

    return [
        *web.rules(),
        *authentication.rules(),
        *authorization.rules(),
        *api.rules(),
    ]


__all__ = [
    "all_generic_rules",
    "api",
    "authentication",
    "authorization",
    "web",
]
