from __future__ import annotations

from typing import Any

from backend.discovery.tls import EXPIRY_WARNING_DAYS
from backend.rules.base import (
    TRANSPORT,
    Finding,
    Rule,
    ScanContext,
)


def tls_record(context: ScanContext) -> dict[str, Any]:
    record = context.attack_surface.get("tls") or {}

    if not isinstance(record, dict) or not record.get("tested"):
        return {}

    return record


class DeprecatedTlsProtocol(Rule):
    id = "GEN-TLS-004"
    title = "Server accepts a deprecated TLS protocol version"
    severity = "medium"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-327"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The endpoint completes a handshake with a protocol version that "
        "is no longer considered secure, so a client can be downgraded "
        "onto it."
    )
    recommendation = (
        "Disable everything below TLS 1.2 and prefer TLS 1.3."
    )
    references = (
        "https://datatracker.ietf.org/doc/html/rfc8996",
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        record = tls_record(context)

        deprecated = record.get("deprecated_protocols") or []

        if not deprecated:
            return []

        return [
            self.finding(
                context,
                severity="high" if "SSLv3" in deprecated else "medium",
                evidence={
                    "deprecated_protocols": deprecated,
                    "supported_protocols": record.get("protocols") or [],
                    "host": record.get("host", ""),
                    "port": record.get("port", 0),
                },
            )
        ]


class WeakTlsCipher(Rule):
    id = "GEN-TLS-005"
    title = "Negotiated TLS cipher suite is weak"
    severity = "medium"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-326"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The suite the server selected uses a broken or export-grade "
        "primitive, so the encryption it provides cannot be relied on."
    )
    recommendation = (
        "Restrict the cipher list to AEAD suites with forward secrecy "
        "(ECDHE with AES-GCM or ChaCha20-Poly1305)."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        record = tls_record(context)

        if not record.get("weak_cipher"):
            return []

        return [
            self.finding(
                context,
                evidence={
                    "cipher": record.get("cipher", ""),
                    "cipher_bits": record.get("cipher_bits", 0),
                    "protocol": record.get("protocol", ""),
                },
            )
        ]


class TlsCertificateExpiry(Rule):
    id = "GEN-TLS-006"
    title = "TLS certificate has expired"
    severity = "high"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-324"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The certificate presented by the server is past its validity "
        "window, so clients cannot distinguish it from an attacker's."
    )
    recommendation = (
        "Renew the certificate and automate renewal so it cannot lapse."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        record = tls_record(context)

        days = record.get("days_until_expiry")

        if days is None:
            return []

        evidence = {
            "expires_at": record.get("expires_at", ""),
            "days_until_expiry": days,
            "subject": record.get("subject", ""),
            "issuer": record.get("issuer", ""),
        }

        if record.get("expired"):
            return [self.finding(context, evidence=evidence)]

        if days <= EXPIRY_WARNING_DAYS:
            return [
                self.finding(
                    context,
                    title="TLS certificate expires soon",
                    severity="low",
                    description=(
                        f"The certificate expires in {days} day(s). An "
                        "expiry that is not renewed in time makes the "
                        "application unreachable or trains users to click "
                        "through certificate warnings."
                    ),
                    evidence=evidence,
                )
            ]

        return []


class UntrustedTlsCertificate(Rule):
    id = "GEN-TLS-007"
    title = "TLS certificate chain does not validate"
    severity = "high"
    confidence = "confirmed"
    category = TRANSPORT
    cwe = "CWE-295"
    owasp = "A02:2021 Cryptographic Failures"
    description = (
        "The certificate chain the server presents is not trusted: it is "
        "self-signed, incomplete or issued for another name. Users who "
        "are taught to bypass the warning cannot detect interception."
    )
    recommendation = (
        "Serve a certificate from a trusted authority for the hostname in "
        "use, including any intermediate certificates in the chain."
    )

    def evaluate(self, context: ScanContext) -> list[Finding]:
        record = tls_record(context)

        if not record.get("reachable") or record.get("trusted"):
            return []

        return [
            self.finding(
                context,
                evidence={
                    "trust_error": record.get("trust_error", ""),
                    "self_signed": record.get("self_signed", False),
                    "host": record.get("host", ""),
                    "port": record.get("port", 0),
                },
            )
        ]


def rules() -> list[Rule]:
    return [
        DeprecatedTlsProtocol(),
        WeakTlsCipher(),
        TlsCertificateExpiry(),
        UntrustedTlsCertificate(),
    ]
