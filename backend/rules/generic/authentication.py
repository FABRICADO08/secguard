from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from backend.rules.base import (
    AUTHENTICATION,
    SESSION,
    Finding,
    Rule,
    ScanContext,
)

SESSION_COOKIE_MARKERS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "xasid",
    "asp.net",
    "jsessionid",
    "phpsessid",
)

SAFE_PASSWORD_AUTOCOMPLETE = (
    "off",
    "new-password",
    "current-password",
)

CSRF_FIELD_MARKERS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "requestverificationtoken",
    "_token",
    "nonce",
)


def _is_session_cookie(name: str) -> bool:
    lowered = str(name or "").lower()

    return any(marker in lowered for marker in SESSION_COOKIE_MARKERS)


def _has_password_field(form: dict[str, Any]) -> bool:
    return any(
        str(field.get("type", "")).lower() == "password"
        for field in form.get("inputs") or []
    )


def _has_csrf_field(form: dict[str, Any]) -> bool:
    for field in form.get("inputs") or []:
        name = str(field.get("name", "")).lower()

        if any(marker in name for marker in CSRF_FIELD_MARKERS):
            return True

    return False


class InsecureSessionCookie(Rule):
    id = "GEN-SES-001"
    title = "Session cookie is missing the Secure flag"
    severity = "medium"
    confidence = "confirmed"
    category = SESSION
    cwe = "CWE-614"
    owasp = "A05:2021 Security Misconfiguration"
    recommendation = (
        "Set the Secure attribute on every cookie so it is only ever sent "
        "over HTTPS."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for cookie in context.cookies:
            if cookie.get("secure"):
                continue

            session_cookie = _is_session_cookie(cookie.get("name", ""))

            findings.append(
                self.finding(
                    context,
                    title=(
                        f"Cookie '{cookie.get('name')}' is missing the "
                        "Secure flag"
                    ),
                    severity=self.severity if session_cookie else "low",
                    description=(
                        f"The cookie '{cookie.get('name')}' is set without "
                        "the Secure attribute, so the browser will also "
                        "send it over unencrypted HTTP connections."
                    ),
                    evidence=cookie,
                )
            )

        return findings


class SessionCookieWithoutHttpOnly(Rule):
    id = "GEN-SES-002"
    title = "Session cookie is missing the HttpOnly flag"
    severity = "medium"
    confidence = "confirmed"
    category = SESSION
    cwe = "CWE-1004"
    owasp = "A05:2021 Security Misconfiguration"
    recommendation = (
        "Set HttpOnly on session and authentication cookies so page "
        "scripts cannot read them."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for cookie in context.cookies:
            if cookie.get("http_only"):
                continue

            if not _is_session_cookie(cookie.get("name", "")):
                continue

            findings.append(
                self.finding(
                    context,
                    title=(
                        f"Session cookie '{cookie.get('name')}' is missing "
                        "the HttpOnly flag"
                    ),
                    description=(
                        f"The session cookie '{cookie.get('name')}' is "
                        "readable from JavaScript, so any cross-site "
                        "scripting flaw can steal the session."
                    ),
                    evidence=cookie,
                )
            )

        return findings


class CookieWithoutSameSite(Rule):
    id = "GEN-SES-003"
    title = "Cookie is missing the SameSite attribute"
    severity = "low"
    confidence = "confirmed"
    category = SESSION
    cwe = "CWE-1275"
    owasp = "A01:2021 Broken Access Control"
    recommendation = (
        "Set SameSite=Lax or SameSite=Strict on cookies, and only use "
        "SameSite=None together with Secure for genuine cross-site flows."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for cookie in context.cookies:
            same_site = str(cookie.get("same_site") or "")

            if same_site and same_site.lower() != "none":
                continue

            if same_site.lower() == "none" and cookie.get("secure"):
                continue

            findings.append(
                self.finding(
                    context,
                    title=(
                        f"Cookie '{cookie.get('name')}' has a weak SameSite "
                        "policy"
                    ),
                    description=(
                        f"The cookie '{cookie.get('name')}' is sent with "
                        f"SameSite={same_site or 'unset'}, so it may be "
                        "attached to cross-site requests and enable "
                        "cross-site request forgery."
                    ),
                    evidence=cookie,
                )
            )

        return findings


class CredentialsOverInsecureChannel(Rule):
    id = "GEN-AUTH-001"
    title = "Credentials are submitted over an insecure channel"
    severity = "high"
    confidence = "confirmed"
    category = AUTHENTICATION
    cwe = "CWE-319"
    owasp = "A02:2021 Cryptographic Failures"
    recommendation = (
        "Point the form action at an HTTPS URL and serve the page that "
        "hosts the form over HTTPS."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for form in context.forms:
            if not _has_password_field(form):
                continue

            action = str(form.get("action") or "")
            page = str(form.get("page") or "")

            action_insecure = urlparse(action).scheme == "http"
            page_insecure = urlparse(page).scheme == "http"

            if not (action_insecure or page_insecure):
                continue

            findings.append(
                self.finding(
                    context,
                    location=page or context.final_url,
                    description=(
                        "A form containing a password field is submitted "
                        "over plain HTTP, so the credentials can be read "
                        "by anyone on the network path."
                    ),
                    evidence={
                        "page": page,
                        "action": action,
                        "method": form.get("method"),
                        "action_over_http": action_insecure,
                        "page_over_http": page_insecure,
                    },
                )
            )

        return findings


class MissingCsrfToken(Rule):
    id = "GEN-AUTH-002"
    title = "State-changing form has no CSRF token"
    severity = "medium"
    confidence = "tentative"
    category = AUTHENTICATION
    cwe = "CWE-352"
    owasp = "A01:2021 Broken Access Control"
    recommendation = (
        "Include a per-session anti-CSRF token in every POST form and "
        "verify it server side, or rely on SameSite cookies plus an origin "
        "check."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for form in context.forms:
            if str(form.get("method", "")).upper() != "POST":
                continue

            if _has_csrf_field(form):
                continue

            findings.append(
                self.finding(
                    context,
                    location=str(form.get("page") or context.final_url),
                    description=(
                        "A POST form was found with no recognizable "
                        "anti-CSRF token field. If the endpoint changes "
                        "state and relies only on cookies, it can be "
                        "triggered from another site."
                    ),
                    evidence={
                        "page": form.get("page"),
                        "action": form.get("action"),
                        "fields": [
                            field.get("name")
                            for field in form.get("inputs") or []
                        ],
                    },
                )
            )

        return findings


class PasswordFieldWithAutocomplete(Rule):
    id = "GEN-AUTH-003"
    title = "Password field allows browser autocomplete"
    severity = "informational"
    confidence = "tentative"
    category = AUTHENTICATION
    cwe = "CWE-522"
    owasp = "A07:2021 Identification and Authentication Failures"
    recommendation = (
        "Set autocomplete=\"new-password\" or \"current-password\" so the "
        "browser handles the field deliberately rather than caching it."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for form in context.forms:
            if not _has_password_field(form):
                continue

            if str(form.get("autocomplete", "")).lower() == "off":
                continue

            if all(
                str(field.get("autocomplete", "")).strip().lower()
                in SAFE_PASSWORD_AUTOCOMPLETE
                for field in form.get("inputs") or []
                if str(field.get("type", "")).lower() == "password"
            ):
                continue

            findings.append(
                self.finding(
                    context,
                    location=str(form.get("page") or context.final_url),
                    description=(
                        "A login form does not disable autocomplete on its "
                        "password field, so the credential may be cached "
                        "by the browser on a shared device."
                    ),
                    evidence={
                        "page": form.get("page"),
                        "action": form.get("action"),
                    },
                )
            )

        return findings


def rules() -> list[Rule]:
    return [
        InsecureSessionCookie(),
        SessionCookieWithoutHttpOnly(),
        CookieWithoutSameSite(),
        CredentialsOverInsecureChannel(),
        MissingCsrfToken(),
        PasswordFieldWithAutocomplete(),
    ]
