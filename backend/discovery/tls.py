from __future__ import annotations

import os
import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests.certs

from backend.config.settings import PROBE_TIMEOUT
from backend.security.targets import (
    BlockedTargetError,
    assert_address_allowed,
    resolve_addresses,
)

# Protocols an internet-facing service should no longer negotiate. TLS 1.1
# and below are deprecated (RFC 8996) and SSL 3 is broken outright.
DEPRECATED_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

TESTABLE_PROTOCOLS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)

# Versions whose suites a current OpenSSL refuses to offer at its default
# security level, so probing them needs the level lowered.
LEGACY_PROTOCOLS = (
    ssl.TLSVersion.SSLv3,
    ssl.TLSVersion.TLSv1,
    ssl.TLSVersion.TLSv1_1,
)

# OpenSSL reasons that mean the local build could not make the offer, as
# opposed to the server turning it down. Treating them as "unsupported by
# the server" would hide a server that still speaks a dead protocol.
LOCAL_FAILURE_REASONS = (
    "NO_PROTOCOLS_AVAILABLE",
    "NO_CIPHERS_AVAILABLE",
    "UNSUPPORTED_PROTOCOL",
)

# DER tags used while reading a certificate's validity window.
EXPLICIT_VERSION = 0xA0
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18

# ASN.1 reads a two-digit year below 50 as 20xx and the rest as 19xx.
UTC_TIME_PIVOT = 2050

# Cipher properties that mean the connection is not forward secret or
# relies on primitives that are no longer considered sound.
WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES",
    "MD5",
    "NULL",
    "EXPORT",
    # Anonymous key exchange: "anon" in IANA names, "ADH"/"AECDH" in
    # OpenSSL names.
    "ANON",
    "ADH-",
    "AECDH-",
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


def is_weak_cipher(name: str) -> bool:
    upper = name.upper()

    return any(marker in upper for marker in WEAK_CIPHER_MARKERS)


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
    timed_out: TimeoutError | None = None

    for address in addresses:
        try:
            sock = socket.create_connection((address, port), timeout=timeout)

        except TimeoutError as exc:
            timed_out = exc

            continue

        except OSError as exc:
            # A name can resolve to an address family the server does not
            # listen on; try the rest before giving up.
            last_error = exc

            continue

        try:
            return context.wrap_socket(sock, server_hostname=host)

        except TimeoutError as exc:
            sock.close()

            timed_out = exc

        except OSError as exc:
            # The same name can serve a healthy and an unhealthy endpoint;
            # a failed handshake on one address says nothing about the rest.
            sock.close()

            last_error = exc

    # An address that never answered leaves the result inconclusive, so a
    # refusal from another address must not bury it.
    raise (
        timed_out
        or last_error
        or OSError(f"Could not connect to {host}:{port}.")
    )


def _ca_bundle() -> tuple[str, str]:
    """
    The trust source requests would use, as (cafile, capath).

    Requests accepts either a bundle file or an OpenSSL-hashed directory,
    so both are honoured here: falling back to the system store instead
    would let the fetch succeed while this inspection calls the same
    chain untrusted.
    """

    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"):
        value = os.environ.get(name, "").strip()

        if not value:
            continue

        if os.path.isdir(value):
            return "", value

        if os.path.isfile(value):
            return value, ""

    bundle = requests.certs.where()

    return (bundle, "") if bundle and os.path.isfile(bundle) else ("", "")


def _default_context(verify: bool) -> ssl.SSLContext:
    cafile, capath = _ca_bundle() if verify else ("", "")

    context = ssl.create_default_context(
        cafile=cafile or None,
        capath=capath or None,
    )

    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


def _pinned_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
    """
    A context that offers exactly one protocol version, or None when the
    local OpenSSL cannot make that offer at all.
    """

    context = _default_context(verify=False)

    if version in LEGACY_PROTOCOLS:
        try:
            # The default security level rejects the only suites these
            # versions have, which would look like a server refusal.
            context.set_ciphers("ALL:@SECLEVEL=0")

        except ssl.SSLError:
            return None

    try:
        with warnings.catch_warnings():
            # Pinning a dead version is deliberate here: the point is to
            # find out whether the server still accepts it.
            warnings.simplefilter("ignore", DeprecationWarning)

            context.minimum_version = version
            context.maximum_version = version

    except (ValueError, OSError):
        return None

    return context


def _is_local_failure(exc: ssl.SSLError) -> bool:
    reason = str(exc.reason or "")
    message = str(exc)

    return any(
        marker in reason or marker in message
        for marker in LOCAL_FAILURE_REASONS
    )


def probe_protocols(
    host: str,
    port: int,
    timeout: int = PROBE_TIMEOUT,
) -> dict[str, list[str]]:
    """
    Report which protocol versions the server agrees to speak.

    Each version is offered on its own connection with certificate
    validation disabled: the question here is what the server negotiates,
    not whether the certificate is trusted. Versions the local OpenSSL
    cannot offer are reported as untested rather than as unsupported, so
    a silent false negative is never presented as a clean result.
    """

    supported: list[str] = []
    untested: list[str] = []

    for label, version in TESTABLE_PROTOCOLS:
        context = _pinned_context(version)

        if context is None:
            untested.append(label)

            continue

        try:
            connection = _connect(host, port, context, timeout)

        except BlockedTargetError:
            raise

        except ssl.SSLError as exc:
            if _is_local_failure(exc):
                untested.append(label)

            continue

        except TimeoutError:
            # A timeout is not a refusal; reporting it as unsupported
            # would hide a server that still speaks the version.
            untested.append(label)

            continue

        except OSError:
            continue

        with connection:
            supported.append(label)

    return {"supported": supported, "untested": untested}


def supported_protocols(
    host: str,
    port: int,
    timeout: int = PROBE_TIMEOUT,
) -> list[str]:
    return probe_protocols(host, port, timeout)["supported"]


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
        # verified it, so an untrusted chain yields no dictionary. An
        # expired certificate is a common reason for that failure, so
        # the expiry is read out of the DER the server still sent.
        _record_expiry(
            certificate_expiry(connection.getpeercert(binary_form=True)),
            result,
        )

        return

    result.update(_names(certificate))

    result["self_signed"] = bool(
        result["subject"]
        and result["subject"] == result["issuer"]
    )

    _record_expiry(
        parse_certificate_date(str(certificate.get("notAfter") or "")),
        result,
    )


def _record_expiry(
    expires: datetime | None,
    result: dict[str, Any],
) -> None:
    if expires is None:
        return

    remaining = expires - datetime.now(timezone.utc)

    result["expires_at"] = expires.isoformat()
    # The whole-day count is for display; the rule compares seconds so a
    # certificate 30 days and 23 hours out is not warned about early.
    result["days_until_expiry"] = remaining.days
    result["seconds_until_expiry"] = remaining.total_seconds()
    result["expired"] = remaining.total_seconds() <= 0


def _read_der(data: bytes, index: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value, returning the tag, value and end."""

    tag = data[index]
    length = data[index + 1]
    index += 2

    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[index:index + count], "big")
        index += count

    end = index + length

    if end > len(data):
        raise ValueError("truncated DER value")

    return tag, data[index:end], end


def certificate_expiry(der: bytes | None) -> datetime | None:
    """
    The `notAfter` of a DER certificate, or None if it cannot be read.

    Only the validity window is decoded, walking the fixed field order of
    `TBSCertificate`: the optional version, serial, signature algorithm
    and issuer come before it.
    """

    if not der:
        return None

    try:
        _, certificate, _ = _read_der(der, 0)
        _, tbs, _ = _read_der(certificate, 0)

        tag, _, index = _read_der(tbs, 0)

        if tag == EXPLICIT_VERSION:
            _, _, index = _read_der(tbs, index)

        for _ in range(2):  # signature algorithm, issuer
            _, _, index = _read_der(tbs, index)

        _, validity, _ = _read_der(tbs, index)

        _, _, index = _read_der(validity, 0)  # notBefore
        tag, value, _ = _read_der(validity, index)

        return _parse_asn1_time(tag, value.decode("ascii"))

    except (IndexError, ValueError, UnicodeDecodeError):
        return None


def _parse_asn1_time(tag: int, value: str) -> datetime | None:
    formats = {
        UTC_TIME: "%y%m%d%H%M%SZ",
        GENERALIZED_TIME: "%Y%m%d%H%M%SZ",
    }

    if tag not in formats:
        return None

    try:
        # Both formats end in Z, so the value is UTC.
        parsed = datetime.strptime(  # noqa: DTZ007
            value,
            formats[tag],
        )

    except ValueError:
        return None

    if tag == UTC_TIME and parsed.year >= UTC_TIME_PIVOT:
        # Python pivots two-digit years at 1969 instead, so everything
        # from 50 to 68 would otherwise land a century too late.
        parsed = parsed.replace(year=parsed.year - 100)

    return parsed.replace(tzinfo=timezone.utc)


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
            "untested_protocols": [],
            "deprecated_protocols": [],
            "weak_cipher": False,
        }

    probe = probe_protocols(host, port, timeout)

    protocols = probe["supported"]

    return {
        "tested": True,
        "host": host,
        "port": port,
        **certificate,
        "protocols": protocols,
        "untested_protocols": probe["untested"],
        "deprecated_protocols": [
            protocol
            for protocol in protocols
            if protocol in DEPRECATED_PROTOCOLS
        ],
        "weak_cipher": is_weak_cipher(certificate["cipher"]),
    }
