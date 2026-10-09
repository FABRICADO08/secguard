"""
Sign in with GitHub and decide which repository results a user may see.

The OAuth handshake spans two requests that may land on different workers —
and the container may restart between them — so pending state and signed-in
sessions are kept in the shared store (backend.storage.sessions); the
cookie only carries a random session id, never the GitHub token.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
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
from backend.storage import sessions as session_store

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
    """Authenticated GitHub profile and repositories visible to that user."""

    login: str
    name: str
    avatar_url: str
    token: str
    repositories: dict[str, dict[str, Any]] = field(default_factory=dict)
    expires: float = 0.0


def enabled() -> bool:
    """Whether GitHub OAuth credentials are configured."""
    return bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET)


# --------------------------------------------------------------------- codec
#
# Session payloads cross processes as JSON. Only JSON types may be stored.


def _encode(user: GitHubUser) -> dict[str, Any]:
    return {
        "login": user.login,
        "name": user.name,
        "avatar_url": user.avatar_url,
        "token": user.token,
        "repositories": user.repositories,
        "expires": user.expires,
    }


def _decode(payload: dict[str, Any]) -> GitHubUser:
    return GitHubUser(
        login=str(payload.get("login") or ""),
        name=str(payload.get("name") or ""),
        avatar_url=str(payload.get("avatar_url") or ""),
        token=str(payload.get("token") or ""),
        repositories=dict(payload.get("repositories") or {}),
        expires=float(payload.get("expires") or 0),
    )


def github_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    """Issue an HTTP request with the shared GitHub request timeout."""
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
    """Load the signed-in user from the session store, if available."""
    session_id = session.get("sid")

    if not session_id:
        return None

    payload = session_store.get("user", session_id)

    if payload is None:
        return None

    return _decode(payload)


def repository_name(application: dict[str, Any]) -> str:
    """Repository full name of a stored application or a listing entry."""

    value = application.get("repository")

    if isinstance(value, dict):
        value = (value.get("repository") or {}).get("name")

    return str(value or "")


def can_view(application: dict[str, Any]) -> bool:
    """Check whether the current user may access a stored application."""
    if application.get("platform") != "Repository" or not enabled():
        return True

    user = current_user()

    return user is not None and repository_name(application).lower() in user.repositories


def visible(applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter application summaries to records visible to the current user."""
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

    page = _landing_page(value)
    if page is None:
        return DEFAULT_LANDING

    query = urlencode(parse_qsl(urlsplit(str(value or "")).query))
    return f"/{page}?{query}" if query else f"/{page}"


def _landing_page(value: str) -> str | None:
    raw = str(value or "")
    parts = urlsplit(raw)
    if parts.scheme or parts.netloc or not raw.startswith("/"):
        return None

    name = parts.path.lstrip("/") or "index.html"
    return next((page for page in LANDING_PAGES if page == name), None)


def _sign_in_failed(status: int):
    """Send the browser back to the sign-in page, which explains the failure."""

    return send_from_directory(FRONTEND, LOGIN_PAGE), status


def _not_configured():
    return jsonify({"success": False, "error": "GitHub sign-in is not configured."}), 404


@blueprint.get("/auth/github/login")
def login():
    """Start the OAuth authorization-code flow with PKCE."""
    if not enabled():
        return _not_configured()

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    # The callback may reach another worker or a restarted container, so the
    # handshake state cannot travel in the signed cookie (Flask cookies are
    # not shared across workers and a new key is drawn on restart when
    # SECGUARD_SECRET_KEY is unset) — keep it in the shared store instead.
    session_store.put(
        "pending",
        state,
        {
            "verifier": verifier,
            "next": safe_next(request.args.get("next", "")),
            "expires": time.time() + session_store.PENDING_TTL_SECONDS,
        },
    )

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


def _exchange_code(code: str, verifier: str) -> str:
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
    return str((exchange.json() or {}).get("access_token") or "")


def _github_profile_and_repositories(token: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    profile_response = _api("GET", "/user", token)
    profile_response.raise_for_status()
    return profile_response.json(), fetch_repositories(token)

def _store_github_session(
    profile: dict[str, Any], token: str, repositories: list[dict[str, Any]]
) -> str:
    session_id = secrets.token_urlsafe(32)
    session_store.put(
        "user",
        session_id,
        _encode(
            GitHubUser(
                login=str(profile.get("login") or ""),
                name=str(profile.get("name") or ""),
                avatar_url=str(profile.get("avatar_url") or ""),
                token=token,
                repositories=repositories,
                expires=time.time() + settings.SESSION_HOURS * 3600,
            )
        ),
    )
    session.clear()
    session["sid"] = session_id
    return session_id


@blueprint.get("/auth/github/callback")
def callback():
    """Validate OAuth state, exchange the code, and persist the session."""
    if not enabled():
        return _not_configured()
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    # Popping makes every state single-use; expired handshakes fail closed.
    pending = session_store.pop("pending", state) if state else None
    if pending is None or not code:
        return _sign_in_failed(400)
    verifier = str(pending.get("verifier") or "")
    landing = safe_next(str(pending.get("next") or ""))
    try:
        token = _exchange_code(code, verifier)
        if not token:
            return _sign_in_failed(400)
        profile, repositories = _github_profile_and_repositories(token)
    except (requests.RequestException, ValueError):
        return _sign_in_failed(502)
    _store_github_session(profile, token, repositories)
    return redirect(landing)


@blueprint.post("/auth/logout")
def logout():
    """Remove the current server-side session and clear its cookie."""
    session_id = session.pop("sid", None)

    if session_id:
        session_store.delete("user", session_id)

    session.clear()

    return jsonify({"success": True})


@blueprint.get("/api/auth/me")
def me():
    """Return authentication status and the current profile summary."""
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
    """Refresh the user's repository permissions from GitHub."""
    user.repositories = fetch_repositories(user.token)

    session_id = session.get("sid")

    if session_id:
        session_store.put("user", session_id, _encode(user))


def dispatch_workflow(user: GitHubUser, repository: dict[str, Any]) -> requests.Response:
    """Request a workflow dispatch on the repository's default branch."""
    owner_repo = repository["name"]

    return _api(
        "POST",
        f"/repos/{owner_repo}/actions/workflows/{settings.GITHUB_WORKFLOW}/dispatches",
        user.token,
        json={"ref": repository["default_branch"]},
    )
