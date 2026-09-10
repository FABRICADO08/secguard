from __future__ import annotations

import os
import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from backend.config.settings import PROBE_TIMEOUT
from backend.security.targets import (
    BlockedTargetError,
    assert_address_allowed,
    resolve_addresses,
)

# Protocols an internet-facing service should no longer negotiate. TLS 1.1
# and below are deprecated (RFC 8996) and SSL 3 is broken outright.
DEPRECATED_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

TESTABLE_PROTOCOLS: tuple[tuple[str, int], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)

# Cipher properties that mean the connection is not forward secret or
# relies on primitives that are no longer considered sound.
WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
)

# Certificates expiring sooner than this need attention before they cause
# an outage; the industry norm for renewal automation is 30 days.
EXPIRY_WARNING_DAYS = 30

CERTIFICATE_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def parse_certificate_date(value: str) -> datetime | None:
    try:
        # OpenSSL always renders notAfter in GMT, so the value is UTC.
        parsed = datetime.strptime(  # noqa: DTZ007
            value,
            CERTIFICATE_DATE_FORMAT,
        )

    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)


def _names(certificate: dict[str, Any]) -> dict[str, Any]:
    subject = {
        key: value
        for entry in certificate.get("subject", ())
        for key, value in entry
    }

    issuer = {
        key: value
        for entry in certificate.get("issuer", ())
        for key, value in entry
    }

    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("commonName", "") or issuer.get(
            "organizationName",
            "",
        ),
        "alternative_names": [
            value
            for kind, value in certificate.get("subjectAltName", ())
            if kind == "DNS"
        ],
    }


def _connect(
    host: str,
    port: int,
    context: ssl.SSLContext,
    timeout: int,
) -> ssl.SSLSocket:
    """
    Open a TLS connection to an address that passed the target policy.

    The connection is made to a checked address rather than to the name,
    so a second DNS answer cannot point the handshake at an internal host
    after the check has run.
    """

    addresses = resolve_addresses(host)

    for address in addresses:
        assert_address_allowed(host, address)

    last_error: OSError | None = None

    for address in addresses:
        try:
            sock = socket.create_connection((address, port), timeout=timeout)

        except OSError as exc:
            # A name can resolve to an address family the server does not
            # listen on; try the rest before giving up.
            last_error = exc

            continue

        try:
            return context.wrap_socket(sock, server_hostname=host)

        except (OSError, ssl.SSLError):
            sock.close()

            raise

    raise last_error or OSError(f"Could not connect to {host}:{port}.")


def _ca_bundle() -> str:
    """
    The CA bundle requests would use, so both agree on what is trusted.
    """

    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"):
        value = os.environ.get(name, "").strip()

        if value and os.path.isfile(value):
            return value

    return ""


def _default_context(verify: bool) -> ssl.SSLContext:
    bundle = _ca_bundle() if verify else ""

    context = ssl.create_default_context(cafile=bundle or None)

    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


def supported_protocols(
    host: str,
    port: int,
    timeout: int = PROBE_TIMEOUT,
) -> list[str]:
    """
    Report which protocol versions the server agrees to speak.

    Each version is offered on its own connection with certificate
    validation disabled: the question here is what the server negotiates,
    not whether the certificate is trusted.
    """

    supported: list[str] = []

    for label, version in TESTABLE_PROTOCOLS:
        context = _default_context(verify=False)

        try:
            with warnings.catch_warnings():
                # Pinning a legacy version is deliberate here: the point
                # is to find out whether the server still accepts it.
                warnings.simplefilter("ignore", DeprecationWarning)

                context.minimum_version = version
                context.maximum_version = version

        except ValueError:
            # The local OpenSSL build refuses to offer this version, so
            # the server's support for it cannot be determined.
            continue

        try:
            connection = _connect(host, port, context, timeout)

        except BlockedTargetError:
            raise

        except (OSError, ssl.SSLError):
            continue

        with connection:
            supported.append(label)

    return supported


def inspect_certificate(
    host: str,
    port: int,
    timeout: int = PROBE_TIMEOUT,
) -> dict[str, Any]:
    """Handshake once and describe the certificate and negotiated suite."""

    result: dict[str, Any] = {
        "reachable": False,
        "trusted": False,
        "trust_error": "",
        "protocol": "",
        "cipher": "",
        "cipher_bits": 0,
        "subject": "",
        "issuer": "",
        "alternative_names": [],
        "self_signed": False,
        "expires_at": "",
        "days_until_expiry": None,
        "expired": False,
    }

    try:
        connection = _connect(host, port, _default_context(verify=True), timeout)

    except ssl.SSLCertVerificationError as exc:
        result["trust_error"] = exc.verify_message or str(exc)

    except (OSError, ssl.SSLError) as exc:
        result["trust_error"] = str(exc)

        # A handshake that fails for a non-trust reason is not worth
        # retrying unverified: the port is not speaking TLS.
        if not isinstance(exc, ssl.SSLError):
            return result

    else:
        with connection:
            result["trusted"] = True

            _describe(connection, result)

        return result

    # The chain did not validate. Reconnect without verification so the
    # certificate itself can still be reported.
    try:
        connection = _connect(host, port, _default_context(verify=False), timeout)

    except (OSError, ssl.SSLError):
        return result

    with connection:
        _describe(connection, result)

    return result


def _describe(connection: ssl.SSLSocket, result: dict[str, Any]) -> None:
    result["reachable"] = True
    result["protocol"] = connection.version() or ""

    cipher = connection.cipher()

    if cipher:
        result["cipher"] = cipher[0]
        result["cipher_bits"] = cipher[2]

    certificate = connection.getpeercert()

    if not certificate:
        # Python only decodes the peer certificate when the connection
        # verified it, so an untrusted chain yields protocol and cipher
        # detail but no certificate fields.
        return

    result.update(_names(certificate))

    result["self_signed"] = bool(
        result["subject"]
        and result["subject"] == result["issuer"]
    )

    expires = parse_certificate_date(str(certificate.get("notAfter") or ""))

    if expires is None:
        return

    remaining = expires - datetime.now(timezone.utc)

    result["expires_at"] = expires.isoformat()
    result["days_until_expiry"] = remaining.days
    result["expired"] = remaining.total_seconds() <= 0


def analyze_tls(url: str, timeout: int = PROBE_TIMEOUT) -> dict[str, Any]:
    """
    Inspect the TLS endpoint behind an https URL.

    Returns an empty record for plain HTTP targets: `GEN-TLS-001` already
    covers those and there is nothing to handshake with.
    """

    parsed = urlparse(url)

    if parsed.scheme != "https" or not parsed.hostname:
        return {"tested": False}

    host = parsed.hostname
    port = parsed.port or 443

    certificate = inspect_certificate(host, port, timeout)

    if not certificate["reachable"]:
        return {
            "tested": True,
            "host": host,
            "port": port,
            **certificate,
            "protocols": [],
            "deprecated_protocols": [],
            "weak_cipher": False,
        }

    protocols = supported_protocols(host, port, timeout)

    cipher = certificate["cipher"].upper()

    return {
        "tested": True,
        "host": host,
        "port": port,
        **certificate,
        "protocols": protocols,
        "deprecated_protocols": [
            protocol
            for protocol in protocols
            if protocol in DEPRECATED_PROTOCOLS
        ],
        "weak_cipher": any(marker in cipher for marker in WEAK_CIPHER_MARKERS),
    }
