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
