from __future__ import annotations

from backend.rules.base import (
    CONFIGURATION,
    Finding,
    Rule,
    ScanContext,
)

# Restrictive directives that fall back to default-src when omitted.
FALLBACK_DIRECTIVES = (
    "object-src",
    "base-uri",
)

UNSAFE_SOURCES = (
    "'unsafe-inline'",
    "'unsafe-eval'",
)

WILDCARD_SOURCES = (
    "*",
    "http:",
    "https:",
    "data:",
)


def parse_policy(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy header into directive -> sources."""

    policy: dict[str, list[str]] = {}

    for part in value.split(";"):
        tokens = part.split()

        if not tokens:
            continue

        name = tokens[0].lower()

        # A repeated directive is ignored by the browser after the first.
        policy.setdefault(name, [token.lower() for token in tokens[1:]])

    return policy


def effective_sources(
    policy: dict[str, list[str]],
    directive: str,
) -> tuple[str, list[str]]:
    """
    Resolve a directive to the sources the browser will actually apply,
    falling back to default-src the way the CSP specification does.
    """

    if directive in policy:
        return directive, policy[directive]

    if "default-src" in policy:
        return "default-src", policy["default-src"]

    return "", []


class CspAllowsUnsafeScriptSources(Rule):
    id = "GEN-CSP-001"
    title = "Content-Security-Policy allows unsafe script sources"
    severity = "medium"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-1021"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The script sources the policy applies permit inline or "
        "dynamically evaluated code, so the policy does not stop the "
        "cross-site scripting it is meant to contain."
    )
    recommendation = (
        "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Move "
        "inline scripts into files, or allow them individually with a "
        "per-response nonce or hash."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        value = context.header("Content-Security-Policy")

        if not value.strip():
            return []

        policy = parse_policy(value)

        directive, sources = effective_sources(policy, "script-src")

        if not directive:
            return []

        unsafe = [source for source in sources if source in UNSAFE_SOURCES]

        if not unsafe:
            return []

        # A nonce or hash makes 'unsafe-inline' inert in browsers that
        # support CSP level 2 or later.
        neutralised = "'unsafe-inline'" in unsafe and any(
            source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
            for source in sources
        )

        if neutralised:
            unsafe = [
                source for source in unsafe if source != "'unsafe-inline'"
            ]

            if not unsafe:
                return []

        return [
            self.finding(
                context,
                severity="high" if "'unsafe-eval'" in unsafe else "medium",
                evidence={
                    "directive": directive,
                    "sources": sources,
                    "unsafe_sources": unsafe,
                },
            )
        ]


class CspAllowsWildcardSources(Rule):
    id = "GEN-CSP-002"
    title = "Content-Security-Policy allows scripts from any origin"
    severity = "medium"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-1021"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The script sources the policy applies include a wildcard or a "
        "bare scheme, so scripts may be loaded from any host and the "
        "policy provides no meaningful restriction."
    )
    recommendation = (
        "List the specific origins that are allowed to serve scripts "
        "instead of '*', 'http:', 'https:' or 'data:'."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        value = context.header("Content-Security-Policy")

        if not value.strip():
            return []

        policy = parse_policy(value)

        # script-src overrides default-src, so only the directive the
        # browser actually applies to scripts is worth reporting.
        directive, sources = effective_sources(policy, "script-src")

        if not directive:
            return []

        wildcards = [
            source for source in sources if source in WILDCARD_SOURCES
        ]

        if not wildcards:
            return []

        return [
            self.finding(
                context,
                title=(
                    f"Content-Security-Policy {directive} allows any origin"
                ),
                evidence={
                    "directive": directive,
                    "sources": sources,
                    "wildcard_sources": wildcards,
                },
            )
        ]


class CspMissingRestrictiveDirectives(Rule):
    id = "GEN-CSP-003"
    title = "Content-Security-Policy omits key restrictions"
    severity = "low"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-1021"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The policy does not set object-src, base-uri or frame-ancestors "
        "and has no default-src to fall back on, leaving plugin content, "
        "base tag injection and framing unrestricted."
    )
    recommendation = (
        "Add object-src 'none', base-uri 'self' and an explicit "
        "frame-ancestors directive, or set a restrictive default-src."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        value = context.header("Content-Security-Policy")

        if not value.strip():
            return []

        policy = parse_policy(value)

        missing = [
            directive
            for directive in FALLBACK_DIRECTIVES
            if not effective_sources(policy, directive)[0]
        ]

        # frame-ancestors never falls back to default-src.
        if "frame-ancestors" not in policy:
            missing.append("frame-ancestors")

        if not missing:
            return []

        return [
            self.finding(
                context,
                description=(
                    "The Content-Security-Policy does not restrict "
                    + ", ".join(sorted(missing))
                    + ", so the browser applies no limit for those."
                ),
                evidence={
                    "missing_directives": sorted(missing),
                    "declared_directives": sorted(policy),
                },
            )
        ]


class CorsAllowsNullOrigin(Rule):
    id = "GEN-CORS-001"
    title = "Cross-origin resource sharing allows the null origin"
    severity = "high"
    confidence = "confirmed"
    category = CONFIGURATION
    cwe = "CWE-942"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The application returns Access-Control-Allow-Origin: null. Any "
        "sandboxed iframe or data: document produces a null origin, so an "
        "attacker-controlled page can read the responses."
    )
    recommendation = (
        "Never allow the null origin. Return an explicit allow-list of "
        "trusted origins instead."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        origin = context.header("Access-Control-Allow-Origin").strip()

        if origin.lower() != "null":
            return []

        return [
            self.finding(
                context,
                evidence={
                    "access_control_allow_origin": origin,
                    "access_control_allow_credentials": (
                        context.header(
                            "Access-Control-Allow-Credentials"
                        ).lower()
                        == "true"
                    ),
                },
            )
        ]


class CorsExposesUnsafeMethods(Rule):
    id = "GEN-CORS-002"
    title = "Cross-origin requests are allowed to use state-changing methods"
    severity = "medium"
    confidence = "firm"
    category = CONFIGURATION
    cwe = "CWE-942"
    owasp = "A01:2021 Broken Access Control"
    description = (
        "The CORS configuration permits state-changing methods from any "
        "origin, so a cross-site page can invoke them directly."
    )
    recommendation = (
        "Restrict Access-Control-Allow-Methods to the methods each origin "
        "genuinely needs, and pair them with an explicit origin allow-list."
    )

    UNSAFE_METHODS = ("put", "delete", "patch")

    def evaluate(self, context: ScanContext) -> list[Finding]:
        origin = context.header("Access-Control-Allow-Origin").strip()

        if origin not in ("*",) and origin.lower() != "null":
            return []

        methods = [
            method.strip().lower()
            for method in context.header(
                "Access-Control-Allow-Methods"
            ).split(",")
            if method.strip()
        ]

        unsafe = [
            method
            for method in methods
            if method in self.UNSAFE_METHODS or method == "*"
        ]

        if not unsafe:
            return []

        return [
            self.finding(
                context,
                evidence={
                    "access_control_allow_origin": origin,
                    "access_control_allow_methods": methods,
                    "unsafe_methods": unsafe,
                },
            )
        ]


def rules() -> list[Rule]:
    return [
        CspAllowsUnsafeScriptSources(),
        CspAllowsWildcardSources(),
        CspMissingRestrictiveDirectives(),
        CorsAllowsNullOrigin(),
        CorsExposesUnsafeMethods(),
    ]
