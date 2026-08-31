from __future__ import annotations

import re

from backend.rules.base import (
    CONFIGURATION,
    INFORMATION_DISCLOSURE,
    TRANSPORT,
    Finding,
    Rule,
    ScanContext,
)


class SecurityHeaderRule(Rule):
    """Base class for a rule that requires a single response header."""

    header_name = ""
    category = CONFIGURATION

    def evaluate(self, context: ScanContext) -> list[Finding]:
        if context.has_header(self.header_name):
            return []

        return [
            self.finding(
                context,
                evidence={
                    "header": self.header_name,
                    "present": False,
                    "observed_headers": sorted(context.headers),
                },
            )
        ]


class MissingContentSecurityPolicy(SecurityHeaderRule):
    id = "GEN-HDR-001"
    header_name = "Content-Security-Policy"
    title = "Content-Security-Policy header is missing"
    severity = "medium"
    confidence = "confirmed"
    cwe = "CWE-1021"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The application does not send a Content-Security-Policy header, "
        "so the browser has no restriction on where scripts, styles and "
        "frames may be loaded from. This removes a key defence against "
        "cross-site scripting and data injection."
    )
    recommendation = (
        "Add a Content-Security-Policy header. Start in report-only mode "
        "with a restrictive default-src policy, review the violation "
        "reports, then enforce it."
    )


class MissingStrictTransportSecurity(Rule):
    id = "GEN-HDR-002"
    title = "Strict-Transport-Security header is missing"
    severity = "medium"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-319"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The HTTPS response does not include a Strict-Transport-Security "
        "header, so a browser may still be downgraded to plain HTTP on a "
        "later visit and the session exposed to interception."
    )
    recommendation = (
        "Send Strict-Transport-Security with a max-age of at least "
        "31536000 seconds, and includeSubDomains once every subdomain "
        "serves HTTPS."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        # HSTS is meaningless over plain HTTP; that is reported separately.
        if not context.is_https:
            return []

        value = context.header("Strict-Transport-Security")

        if not value:
            return [
                self.finding(
                    context,
                    evidence={
                        "header": "Strict-Transport-Security",
                        "present": False,
                    },
                )
            ]

        match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)

        max_age = int(match.group(1)) if match else 0

        if max_age < 31536000:
            return [
                self.finding(
                    context,
                    title=(
                        "Strict-Transport-Security max-age is too short"
                    ),
                    severity="low",
                    description=(
                        "The Strict-Transport-Security header is present "
                        f"but max-age is {max_age} seconds, which is less "
                        "than the recommended one year."
                    ),
                    evidence={
                        "header": "Strict-Transport-Security",
                        "value": value,
                        "max_age": max_age,
                        "recommended_max_age": 31536000,
                    },
                )
            ]

        return []


class MissingXContentTypeOptions(SecurityHeaderRule):
    id = "GEN-HDR-003"
    header_name = "X-Content-Type-Options"
    title = "X-Content-Type-Options header is missing"
    severity = "low"
    confidence = "confirmed"
    cwe = "CWE-16"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "Without X-Content-Type-Options: nosniff a browser may guess the "
        "content type of a response and execute a file that was never "
        "meant to be script."
    )
    recommendation = "Send X-Content-Type-Options: nosniff on every response."


class MissingFrameProtection(Rule):
    id = "GEN-HDR-004"
    title = "Clickjacking protection is missing"
    severity = "medium"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-1021"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "Neither X-Frame-Options nor a Content-Security-Policy "
        "frame-ancestors directive is present, so the application can be "
        "embedded in a hostile page and used for clickjacking."
    )
    recommendation = (
        "Send Content-Security-Policy: frame-ancestors 'self' (or 'none'), "
        "and X-Frame-Options: SAMEORIGIN for older browsers."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        frame_options = context.header("X-Frame-Options")

        csp = context.header("Content-Security-Policy").lower()

        if frame_options or "frame-ancestors" in csp:
            return []

        return [
            self.finding(
                context,
                evidence={
                    "x_frame_options": frame_options,
                    "csp_frame_ancestors": False,
                },
            )
        ]


class MissingReferrerPolicy(SecurityHeaderRule):
    id = "GEN-HDR-005"
    header_name = "Referrer-Policy"
    title = "Referrer-Policy header is missing"
    severity = "low"
    confidence = "confirmed"
    cwe = "CWE-200"
    owasp = "A01:2021 Broken Access Control"
    description = (
        "No Referrer-Policy is set, so full URLs — including any tokens or "
        "identifiers they contain — may be sent to third-party sites."
    )
    recommendation = (
        "Send Referrer-Policy: strict-origin-when-cross-origin or stricter."
    )


class MissingPermissionsPolicy(SecurityHeaderRule):
    id = "GEN-HDR-006"
    header_name = "Permissions-Policy"
    title = "Permissions-Policy header is missing"
    severity = "informational"
    confidence = "confirmed"
    cwe = "CWE-16"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "No Permissions-Policy is set, so embedded content can request "
        "powerful browser features such as camera, microphone and "
        "geolocation."
    )
    recommendation = (
        "Send a Permissions-Policy header that disables the features the "
        "application does not use."
    )


class PermissiveCorsPolicy(Rule):
    id = "GEN-HDR-007"
    title = "Cross-origin resource sharing is unrestricted"
    severity = "medium"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-942"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The application returns Access-Control-Allow-Origin: * so any "
        "site can read its responses."
    )
    recommendation = (
        "Return an explicit allow-list of trusted origins instead of a "
        "wildcard, and never combine a wildcard with credentials."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        origin = context.header("Access-Control-Allow-Origin").strip()

        if origin != "*":
            return []

        credentials = (
            context.header("Access-Control-Allow-Credentials").lower()
            == "true"
        )

        return [
            self.finding(
                context,
                severity="high" if credentials else self.severity,
                description=(
                    self.description
                    + (
                        " Credentials are also allowed, which browsers "
                        "reject but which signals an unsafe CORS "
                        "configuration."
                        if credentials
                        else ""
                    )
                ),
                evidence={
                    "access_control_allow_origin": origin,
                    "access_control_allow_credentials": credentials,
                },
            )
        ]


class InsecureTransport(Rule):
    id = "GEN-TLS-001"
    title = "Application is served over plain HTTP"
    severity = "high"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-319"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The application responds over HTTP, so all traffic — including "
        "credentials and session cookies — travels unencrypted."
    )
    recommendation = (
        "Serve the application over HTTPS only and redirect HTTP to HTTPS."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        if context.is_https:
            return []

        return [
            self.finding(
                context,
                evidence={
                    "final_url": context.final_url,
                    "scheme": "http",
                },
            )
        ]


class MissingHttpsRedirect(Rule):
    id = "GEN-TLS-002"
    title = "Plain HTTP is served without redirecting to HTTPS"
    severity = "medium"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-319"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The HTTP origin answers without redirecting to HTTPS, so a user "
        "or link that omits the scheme stays on an unencrypted connection."
    )
    recommendation = (
        "Redirect every HTTP request to the HTTPS equivalent with a 301 "
        "before any content is served."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        redirect = context.response.get("http_redirect") or {}

        if not redirect.get("tested"):
            return []

        if redirect.get("redirects_to_https"):
            return []

        return [
            self.finding(
                context,
                location=redirect.get("http_url", context.final_url),
                evidence=redirect,
            )
        ]


class MixedContent(Rule):
    id = "GEN-TLS-003"
    title = "HTTPS page loads resources over HTTP"
    severity = "medium"
    confidence = "firm"
    category = TRANSPORT
    cwe = "CWE-311"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "An HTTPS page references scripts served over plain HTTP. Browsers "
        "block or downgrade such resources and an attacker on the network "
        "can replace them."
    )
    recommendation = (
        "Load every subresource over HTTPS and add "
        "upgrade-insecure-requests to the Content-Security-Policy."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        if not context.is_https:
            return []

        insecure = [
            script
            for script in context.scripts
            if script.lower().startswith("http://")
        ]

        if not insecure:
            return []

        return [
            self.finding(
                context,
                evidence={
                    "insecure_scripts": insecure[:20],
                    "insecure_script_count": len(insecure),
                },
            )
        ]


class ServerBannerDisclosure(Rule):
    id = "GEN-INF-001"
    title = "Server software version is disclosed"
    severity = "informational"
    confidence = "confirmed"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-200"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "Response headers reveal the server software and its version, "
        "which helps an attacker select known exploits."
    )
    recommendation = (
        "Suppress or genericise the Server, X-Powered-By, X-AspNet-Version "
        "and X-Generator headers."
    )

    BANNER_HEADERS = (
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    )

    VERSION_PATTERN = re.compile(r"\d+\.\d+")

    def evaluate(self, context: ScanContext) -> list[Finding]:
        disclosed = {
            name: context.headers[name]
            for name in self.BANNER_HEADERS
            if context.headers.get(name)
            and self.VERSION_PATTERN.search(context.headers[name])
        }

        if not disclosed:
            return []

        return [
            self.finding(
                context,
                evidence={"headers": disclosed},
            )
        ]


class DirectoryListingEnabled(Rule):
    id = "GEN-INF-002"
    title = "Directory listing is enabled"
    severity = "medium"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-548"
    owasp = "A01:2021 Broken Access Control"
    description = (
        "A crawled page returns an automatically generated directory "
        "index, exposing the file layout of the server."
    )
    recommendation = (
        "Disable automatic directory indexes and serve an explicit index "
        "document or a 403 instead."
    )

    MARKERS = (
        re.compile(r"<title>\s*index of\s*/", re.IGNORECASE),
        re.compile(r"<h1>\s*index of\s*/", re.IGNORECASE),
        re.compile(
            r"<title>\s*directory listing for",
            re.IGNORECASE,
        ),
        re.compile(r"\[to parent directory\]", re.IGNORECASE),
    )

    LINK_PATTERN = re.compile(r"<a\s[^>]*href=", re.IGNORECASE)

    def evaluate(self, context: ScanContext) -> list[Finding]:
        body = context.body

        matched = [
            marker.pattern
            for marker in self.MARKERS
            if marker.search(body)
        ]

        if not matched or not self.LINK_PATTERN.search(body):
            return []

        return [
            self.finding(
                context,
                evidence={"markers": matched},
            )
        ]


def rules() -> list[Rule]:
    return [
        MissingContentSecurityPolicy(),
        MissingStrictTransportSecurity(),
        MissingXContentTypeOptions(),
        MissingFrameProtection(),
        MissingReferrerPolicy(),
        MissingPermissionsPolicy(),
        PermissiveCorsPolicy(),
        InsecureTransport(),
        MissingHttpsRedirect(),
        MixedContent(),
        ServerBannerDisclosure(),
        DirectoryListingEnabled(),
    ]
