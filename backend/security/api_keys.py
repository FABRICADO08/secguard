"""Scoped, expiring API keys (``sgk_<id>_<secret>``); only a SHA-256 hash of the secret is stored."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.storage import portfolio_settings

PREFIX = "sgk_"

SCOPES = ("scan", "admin")

DEFAULT_DAYS = 90

MAX_DAYS = 365

_DOCUMENT = "api_keys"

_TOKEN = re.compile(r"sgk_([0-9a-f]{12})_([A-Za-z0-9_-]{20,128})")

PUBLIC_FIELDS = ("id", "name", "scopes", "created_at", "created_by", "expires_at", "revoked_at")


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _keys() -> dict[str, dict[str, Any]]:
    keys = portfolio_settings.load(_DOCUMENT).get("keys")
    return dict(keys) if isinstance(keys, dict) else {}


def _save(keys: dict[str, dict[str, Any]]) -> None:
    portfolio_settings.save(_DOCUMENT, {"keys": keys})


def _active(record: dict[str, Any], now: datetime | None = None) -> bool:
    return not record.get("revoked_at") and str(record.get("expires_at") or "") > _now(now).isoformat()


def public(record: dict[str, Any]) -> dict[str, Any]:
    return {**{name: record.get(name) for name in PUBLIC_FIELDS}, "active": _active(record)}


def listing() -> list[dict[str, Any]]:
    return sorted((public(record) for record in _keys().values()), key=lambda item: item["created_at"], reverse=True)


def clean_request(payload: dict[str, Any]) -> tuple[str, list[str], int, str]:
    """Validate a create request; returns name, scopes, days and an error message."""
    name = str(payload.get("name") or "").strip()
    scopes = payload.get("scopes")
    days = payload.get("expires_in_days", DEFAULT_DAYS)
    if not 1 <= len(name) <= 100:
        return "", [], 0, "Give the key a name of 1 to 100 characters."
    if not isinstance(scopes, list) or not scopes or not set(scopes) <= set(SCOPES):
        return "", [], 0, f"scopes must be a non-empty list drawn from {', '.join(SCOPES)}."
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        return "", [], 0, f"expires_in_days must be a whole number from 1 to {MAX_DAYS}."
    return name, sorted(set(scopes)), days, ""


def create(name: str, scopes: list[str], days: int, created_by: str,
           now: datetime | None = None) -> tuple[dict[str, Any], str]:
    """Store a new key and return its public record and the token, which is shown only once."""
    key_id, secret = secrets.token_hex(6), secrets.token_urlsafe(32)
    moment = _now(now)
    record = {
        "id": key_id,
        "name": name,
        "scopes": scopes,
        "hash": _hash(secret),
        "created_at": moment.isoformat(),
        "created_by": created_by,
        "expires_at": (moment + timedelta(days=days)).isoformat(),
        "revoked_at": None,
    }
    keys = _keys()
    keys[key_id] = record
    _save(keys)
    return public(record), f"{PREFIX}{key_id}_{secret}"


def revoke(key_id: str, now: datetime | None = None) -> bool:
    keys = _keys()
    record = keys.get(key_id)
    if record is None:
        return False
    if not record.get("revoked_at"):
        record["revoked_at"] = _now(now).isoformat()
        _save(keys)
    return True


def lookup(token: str, now: datetime | None = None) -> dict[str, Any] | None:
    """The active key a token belongs to, or None."""
    match = _TOKEN.fullmatch(token)
    if match is None:
        return None
    record = _keys().get(match.group(1))
    if record is None or not hmac.compare_digest(str(record.get("hash") or ""), _hash(match.group(2))):
        return None
    return record if _active(record, now) else None
