from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))

    except (TypeError, ValueError):
        return default


USER_AGENT = os.environ.get(
    "SECGUARD_USER_AGENT",
    "Application-Security-Platform/0.2 (authorized-security-discovery)",
)

# Timeout for the initial fingerprint request.
FETCH_TIMEOUT = _int_env("SECGUARD_FETCH_TIMEOUT", 20)

# Timeout for each crawled page.
CRAWL_TIMEOUT = _int_env("SECGUARD_CRAWL_TIMEOUT", 15)

# Timeout for lightweight existence probes.
PROBE_TIMEOUT = _int_env("SECGUARD_PROBE_TIMEOUT", 8)

MAX_CRAWL_PAGES = _int_env("SECGUARD_MAX_CRAWL_PAGES", 20)


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def _list_env(name: str) -> frozenset[str]:
    return frozenset(
        item.strip().lower()
        for item in os.environ.get(name, "").split(",")
        if item.strip()
    )


# Shared secret required by the scanning and delete endpoints. When it is
# empty those endpoints only answer requests from the loopback interface,
# so a default install stays usable locally but is never remotely driveable.
API_TOKEN = os.environ.get("SECGUARD_API_TOKEN", "").strip()

# Scanning a target that resolves to a private, loopback or otherwise
# internal address is server-side request forgery unless it is deliberate,
# so it has to be switched on.
ALLOW_PRIVATE_TARGETS = _bool_env("SECGUARD_ALLOW_PRIVATE_TARGETS")

# Hostnames that may be scanned regardless of the address they resolve to,
# e.g. "localhost,127.0.0.1" for the bundled fixture server.
ALLOWED_TARGET_HOSTS = _list_env("SECGUARD_ALLOWED_TARGET_HOSTS")

# Fixed-window rate limit applied per client address to the scanning
# endpoints, which each fan out into dozens of outbound requests.
RATE_LIMIT_REQUESTS = _int_env("SECGUARD_RATE_LIMIT_REQUESTS", 10)

RATE_LIMIT_WINDOW_SECONDS = _int_env("SECGUARD_RATE_LIMIT_WINDOW", 60)
