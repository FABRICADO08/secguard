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

db_url = os.environ.get("POSTGRES_URL") 


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

# GitHub sign-in. With a client id and secret configured, repository
# results are only shown to signed-in users whose GitHub account can read
# the repository.
GITHUB_CLIENT_ID = os.environ.get("SECGUARD_GITHUB_CLIENT_ID", "").strip()

GITHUB_CLIENT_SECRET = os.environ.get("SECGUARD_GITHUB_CLIENT_SECRET", "").strip()

# Must match the callback URL registered on the OAuth app; derived from the
# request when empty.
GITHUB_CALLBACK_URL = os.environ.get("SECGUARD_GITHUB_CALLBACK_URL", "").strip()

# `repo` is needed to see private repositories and to start workflow runs.
GITHUB_SCOPES = os.environ.get("SECGUARD_GITHUB_SCOPES", "repo read:user")

GITHUB_URL = os.environ.get("SECGUARD_GITHUB_URL", "https://github.com").rstrip("/")

GITHUB_API_URL = os.environ.get("SECGUARD_GITHUB_API_URL", "https://api.github.com").rstrip("/")

# Workflow file started by "Run scan".
GITHUB_WORKFLOW = os.environ.get("SECGUARD_GITHUB_WORKFLOW", "secguard.yml")

# Signs the session cookie. A random key is used when unset, which signs
# everyone out whenever the server restarts.
SECRET_KEY = os.environ.get("SECGUARD_SECRET_KEY", "").strip()

SESSION_COOKIE_SECURE = _bool_env("SECGUARD_SECURE_COOKIES")

SESSION_HOURS = _int_env("SECGUARD_SESSION_HOURS", 8)
