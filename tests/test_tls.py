from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from datetime import datetime, timedelta, timezone

import pytest

from backend.discovery.tls import (
    analyze_tls,
    inspect_certificate,
    parse_certificate_date,
    supported_protocols,
)
from tests.test_generic_rules import make_context, rule_ids, run


def tls_surface(**overrides):
    record = {
        "tested": True,
        "host": "app.test",
        "port": 443,
        "reachable": True,
        "trusted": True,
        "trust_error": "",
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "protocols": ["TLSv1.2", "TLSv1.3"],
        "deprecated_protocols": [],
        "weak_cipher": False,
        "subject": "app.test",
        "issuer": "Test CA",
        "self_signed": False,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "days_until_expiry": 900,
        "expired": False,
    }

    record.update(overrides)

    return {"tls": record}


def test_certificate_date_is_parsed_as_utc():
    parsed = parse_certificate_date("Jan  5 12:00:00 2030 GMT")

    assert parsed == datetime(2030, 1, 5, 12, 0, tzinfo=timezone.utc)


def test_unparseable_certificate_date_is_none():
    assert parse_certificate_date("not a date") is None


def test_plain_http_target_is_not_probed():
    assert analyze_tls("http://app.test/") == {"tested": False}


# ------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------

def test_healthy_tls_produces_no_transport_findings():
    findings = rule_ids(run(make_context(attack_surface=tls_surface())))

    assert not {
        "GEN-TLS-004",
        "GEN-TLS-005",
        "GEN-TLS-006",
        "GEN-TLS-007",
    } & findings


def test_missing_tls_record_produces_no_findings():
    findings = rule_ids(run(make_context(attack_surface={})))

    assert "GEN-TLS-004" not in findings


def test_deprecated_protocol_is_reported():
    findings = run(
        make_context(
            attack_surface=tls_surface(
                protocols=["TLSv1", "TLSv1.2"],
                deprecated_protocols=["TLSv1"],
            )
        )
    )

    assert "GEN-TLS-004" in rule_ids(findings)


def test_sslv3_raises_protocol_severity():
    findings = run(
        make_context(
            attack_surface=tls_surface(
                protocols=["SSLv3", "TLSv1.2"],
                deprecated_protocols=["SSLv3", "TLSv1"],
            )
        )
    )

    protocol = [f for f in findings if f["rule_id"] == "GEN-TLS-004"]

    assert protocol and protocol[0]["severity"] == "high"


def test_weak_cipher_is_reported():
    findings = run(
        make_context(
            attack_surface=tls_surface(
                cipher="ECDHE-RSA-DES-CBC3-SHA",
                weak_cipher=True,
            )
        )
    )

    assert "GEN-TLS-005" in rule_ids(findings)


def test_expired_certificate_is_high():
    findings = run(
        make_context(
            attack_surface=tls_surface(
                expired=True,
                days_until_expiry=-3,
            )
        )
    )

    expiry = [f for f in findings if f["rule_id"] == "GEN-TLS-006"]

    assert expiry and expiry[0]["severity"] == "high"


def test_certificate_expiring_soon_is_low():
    findings = run(
        make_context(attack_surface=tls_surface(days_until_expiry=9))
    )

    expiry = [f for f in findings if f["rule_id"] == "GEN-TLS-006"]

    assert expiry and expiry[0]["severity"] == "low"


def test_untrusted_chain_is_reported():
    findings = run(
        make_context(
            attack_surface=tls_surface(
                trusted=False,
                self_signed=True,
                trust_error="self signed certificate",
            )
        )
    )

    assert "GEN-TLS-007" in rule_ids(findings)


def test_unreachable_tls_port_reports_nothing():
    findings = rule_ids(
        run(
            make_context(
                attack_surface=tls_surface(
                    reachable=False,
                    trusted=False,
                    days_until_expiry=None,
                )
            )
        )
    )

    assert not {"GEN-TLS-004", "GEN-TLS-006", "GEN-TLS-007"} & findings


# ------------------------------------------------------------------
# Live handshake against a local self-signed server
# ------------------------------------------------------------------

@pytest.fixture(scope="module")
def self_signed_certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls")

    certificate = directory / "cert.pem"
    key = directory / "key.pem"

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "5",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )

    return certificate, key


@pytest.fixture()
def tls_server(self_signed_certificate, monkeypatch):
    monkeypatch.setenv("SECGUARD_ALLOW_PRIVATE_TARGETS", "1")

    from backend.config import settings

    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)

    certificate, key = self_signed_certificate

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client, _ = listener.accept()

            except OSError:
                return

            try:
                with context.wrap_socket(client, server_side=True) as tls:
                    tls.recv(1024)

            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    yield listener.getsockname()[1]

    stop.set()
    listener.close()
    thread.join(timeout=2)


def test_self_signed_server_is_reported_as_untrusted(tls_server):
    result = inspect_certificate("127.0.0.1", tls_server, timeout=5)

    assert result["reachable"]
    assert not result["trusted"]
    assert result["trust_error"]
    assert result["protocol"].startswith("TLS")


def test_supported_protocols_excludes_versions_the_server_refuses(tls_server):
    protocols = supported_protocols("127.0.0.1", tls_server, timeout=5)

    assert "TLSv1.2" in protocols or "TLSv1.3" in protocols
    assert "SSLv3" not in protocols


def test_analyze_tls_reports_the_endpoint(tls_server):
    result = analyze_tls(f"https://127.0.0.1:{tls_server}/", timeout=5)

    assert result["tested"]
    assert result["host"] == "127.0.0.1"
    assert result["port"] == tls_server
    assert result["protocols"]
    assert not result["trusted"]


def test_short_lived_certificate_is_flagged_by_the_expiry_rule():
    soon = datetime.now(timezone.utc) + timedelta(days=3)

    findings = run(
        make_context(
            attack_surface=tls_surface(
                days_until_expiry=3,
                expires_at=soon.isoformat(),
            )
        )
    )

    assert "GEN-TLS-006" in rule_ids(findings)
