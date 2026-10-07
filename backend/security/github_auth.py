"""
Sign in with GitHub and decide which repository results a user may see.

Sessions live in process memory (the server runs a single worker); the
cookie only carries a random session id, never the GitHub token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import requests
from flask import (
    Blueprint,
    jsonify,
    redirect,
    request,
    send_from_directory,
    session,
)

from backend.config import settings

TIMEOUT = 15

MAX_REPOSITORY_PAGES = 10

blueprint = Blueprint("github_auth", __name__)

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"

LOGIN_PAGE = "login.html"

DEFAULT_LANDING = "/applications.html"

# Pages a sign-in may return to; anything else lands on My Applications.
LANDING_PAGES = frozenset(
    page.name for page in FRONTEND.glob("*.html") if page.name != LOGIN_PAGE
)


@dataclass
class GitHubUser:
    login: str
    name: str
    avatar_url: str
    token: str
    repositories: dict[str, dict[str, Any]] = field(default_factory=dict)
    expires: float = 0.0


_sessions: dict[str, GitHubUser] = {}

_lock = threading.Lock()


def enabled() -> bool:
    return bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET)


def github_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return requests.request(method, url, timeout=TIMEOUT, **kwargs)


def _api(method: str, path: str, token: str, **kwargs: Any) -> requests.Response:
    return github_request(
        method,
        f"{settings.GITHUB_API_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        **kwargs,
    )


def fetch_repositories(token: str) -> dict[str, dict[str, Any]]:
    """Every repository the token's user can read, keyed by lower-case full name."""

    repositories: dict[str, dict[str, Any]] = {}

    for page in range(1, MAX_REPOSITORY_PAGES + 1):
        response = _api(
            "GET",
            "/user/repos",
            token,
            params={"per_page": 100, "page": page, "affiliation": "owner,collaborator,organization_member"},
        )

        response.raise_for_status()

        items = response.json()

        for item in items:
            permissions = item.get("permissions") or {}

            if not permissions.get("pull"):
                continue

            repositories[str(item["full_name"]).lower()] = {
                "name": item["full_name"],
                "private": bool(item.get("private")),
                "html_url": item.get("html_url") or "",
                "default_branch": item.get("default_branch") or "main",
                "description": item.get("description") or "",
                "can_trigger": bool(permissions.get("push") or permissions.get("admin")),
            }

        if len(items) < 100:
            break

    return repositories


def current_user() -> GitHubUser | None:
    session_id = session.get("sid")

    if not session_id:
        return None

    with _lock:
        user = _sessions.get(session_id)

        if user is not None and user.expires < time.time():
            _sessions.pop(session_id, None)
            user = None

    return user


def repository_name(application: dict[str, Any]) -> str:
    """Repository full name of a stored application or a listing entry."""

    value = application.get("repository")

    if isinstance(value, dict):
        value = (value.get("repository") or {}).get("name")

    return str(value or "")


def can_view(application: dict[str, Any]) -> bool:
    if application.get("platform") != "Repository" or not enabled():
        return True

    user = current_user()

    return user is not None and repository_name(application).lower() in user.repositories


def visible(applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [application for application in applications if can_view(application)]


def _callback_url() -> str:
    """
    The redirect_uri sent to GitHub. It must match the callback URL
    registered on the OAuth app exactly, so it is always the fixed
    /auth/github/callback route; SECGUARD_GITHUB_CALLBACK_URL overrides
    the public address when it cannot be derived from the request.
    """

    return settings.GITHUB_CALLBACK_URL or f"{request.host_url.rstrip('/')}/auth/github/callback"


def safe_next(value: str) -> str:
    """The SecGuard page to return to after sign-in, never another site."""

    parts = urlsplit(str(value or ""))

    if parts.scheme or parts.netloc or not str(value or "").startswith("/"):
        return DEFAULT_LANDING

    name = parts.path.lstrip("/") or "index.html"
    page = next((page for page in LANDING_PAGES if page == name), None)

    if page is None:
        return DEFAULT_LANDING

    query = urlencode(parse_qsl(parts.query))

    return f"/{page}?{query}" if query else f"/{page}"


def _sign_in_failed(status: int):
    """Send the browser back to the sign-in page, which explains the failure."""

    return send_from_directory(FRONTEND, LOGIN_PAGE), status


def _not_configured():
    return jsonify({"success": False, "error": "GitHub sign-in is not configured."}), 404


@blueprint.get("/auth/github/login")
def login():
    if not enabled():
        return _not_configured()

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    session["oauth_state"] = state
    session["oauth_verifier"] = verifier
    session["next"] = safe_next(request.args.get("next", ""))

    query = urlencode(
        {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": _callback_url(),
            "scope": settings.GITHUB_SCOPES,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    return redirect(f"{settings.GITHUB_URL}/login/oauth/authorize?{query}")


@blueprint.get("/auth/github/callback")
def callback():
    if not enabled():
        return _not_configured()

    expected = session.pop("oauth_state", "")
    verifier = session.pop("oauth_verifier", "")
    landing = safe_next(session.pop("next", ""))
    state = request.args.get("state", "")
    code = request.args.get("code", "")

    if not expected or not code or not hmac.compare_digest(state, expected):
        return _sign_in_failed(400)

    try:
        exchange = github_request(
            "POST",
            f"{settings.GITHUB_URL}/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": _callback_url(),
                "code_verifier": verifier,
            },
        )

        token = str((exchange.json() or {}).get("access_token") or "")

        if not token:
            return _sign_in_failed(400)

        profile_response = _api("GET", "/user", token)
        profile_response.raise_for_status()
        profile = profile_response.json()

        repositories = fetch_repositories(token)

    except (requests.RequestException, ValueError):
        return _sign_in_failed(502)

    session_id = secrets.token_urlsafe(32)

    with _lock:
        now = time.time()

        for key in [key for key, user in _sessions.items() if user.expires < now]:
            _sessions.pop(key, None)

        _sessions[session_id] = GitHubUser(
            login=str(profile.get("login") or ""),
            name=str(profile.get("name") or ""),
            avatar_url=str(profile.get("avatar_url") or ""),
            token=token,
            repositories=repositories,
            expires=now + settings.SESSION_HOURS * 3600,
        )

    session.clear()
    session["sid"] = session_id

    return redirect(landing)


@blueprint.post("/auth/logout")
def logout():
    session_id = session.pop("sid", None)

    if session_id:
        with _lock:
            _sessions.pop(session_id, None)

    session.clear()

    return jsonify({"success": True})


@blueprint.get("/api/auth/me")
def me():
    user = current_user()

    return jsonify(
        {
            "success": True,
            "github_enabled": enabled(),
            "authenticated": user is not None,
            "user": (
                {"login": user.login, "name": user.name, "avatar_url": user.avatar_url, "repositories": len(user.repositories)}
                if user
                else None
            ),
        }
    )


def refresh_repositories(user: GitHubUser) -> None:
    repositories = fetch_repositories(user.token)

    with _lock:
        user.repositories = repositories


def dispatch_workflow(user: GitHubUser, repository: dict[str, Any]) -> requests.Response:
    owner_repo = repository["name"]

    return _api(
        "POST",
        f"/repos/{owner_repo}/actions/workflows/{settings.GITHUB_WORKFLOW}/dispatches",
        user.token,
        json={"ref": repository["default_branch"]},
    )
