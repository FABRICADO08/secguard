from __future__ import annotations

import re

from backend.rules.base import (
    INFORMATION_DISCLOSURE,
    Finding,
    Rule,
    ScanContext,
)

# Each pattern is (label, compiled pattern). Patterns are deliberately
# anchored on provider-specific shapes so a random hex string in the page
# does not produce a finding.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}")),
    (
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "Hardcoded credential assignment",
        re.compile(
            r"""(?:api[_-]?key|secret[_-]?key|client[_-]?secret|"""
            r"""access[_-]?token|password)\s*[:=]\s*"""
            r"""["'][^"'\s]{12,}["']""",
            re.IGNORECASE,
        ),
    ),
)

PLACEHOLDER_MARKERS = (
    "example",
    "changeme",
    "placeholder",
    "your_",
    "your-",
    "xxxx",
    "dummy",
    "<",
    "{{",
    "${",
)

SCRIPT_BLOCK = re.compile(
    r"<script\b[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)

SOURCE_MAP = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"'<>]+)",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    lowered = value.lower()

    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def redact(value: str) -> str:
    """Keep enough of a match to locate it without leaking the secret."""

    stripped = value.strip()

    if len(stripped) <= 8:
        return "*" * len(stripped)

    return f"{stripped[:4]}...{stripped[-2:]}"


def inline_scripts(body: str) -> list[str]:
    return [block for block in SCRIPT_BLOCK.findall(body) if block.strip()]


class ClientSideSecret(Rule):
    id = "GEN-JS-001"
    title = "Secret material is embedded in client-side code"
    severity = "high"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-798"
    owasp = "A07:2021 Identification and Authentication Failures"
    description = (
        "An inline script contains what looks like a credential. Anything "
        "served to the browser is readable by every visitor, so a key "
        "embedded here must be treated as public."
    )
    recommendation = (
        "Move the credential server-side and revoke the exposed value. "
        "Where the browser genuinely needs access, proxy the call through "
        "your own backend or issue a short-lived scoped token."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings = []

        for script in inline_scripts(context.body):
            for label, pattern in SECRET_PATTERNS:
                match = pattern.search(script)

                if not match or is_placeholder(match.group(0)):
                    continue

                findings.append(
                    self.finding(
                        context,
                        title=f"{label} is embedded in client-side code",
                        evidence={
                            "kind": label,
                            "match": redact(match.group(0)),
                        },
                    )
                )

        return findings


class ExposedSourceMap(Rule):
    id = "GEN-JS-002"
    title = "Source map reference is exposed to the browser"
    severity = "low"
    confidence = "firm"
    category = INFORMATION_DISCLOSURE
    cwe = "CWE-540"
    owasp = "A05:2021 Security Misconfiguration"
    description = (
        "The page references a source map. If the map is reachable it "
        "reveals the original, unminified source, including comments and "
        "internal paths."
    )
    recommendation = (
        "Do not deploy source maps to production, or restrict them to "
        "authenticated internal users."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        match = SOURCE_MAP.search(context.body)

        if not match:
            return []

        return [
            self.finding(
                context,
                evidence={"source_map": match.group(1)},
            )
        ]


def rules() -> list[Rule]:
    return [
        ClientSideSecret(),
        ExposedSourceMap(),
    ]
