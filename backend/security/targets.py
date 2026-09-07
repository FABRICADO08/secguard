from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from backend.config import settings


class BlockedTargetError(requests.RequestException):
    """
    The requested target is not an allowed scan destination.

    Derived from `requests.RequestException` so that a redirect into a
    blocked address aborts the outbound request like any other transport
    failure instead of escaping through the discovery pipeline.
    """


def _is_internal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def resolve_addresses(host: str) -> list[str]:
    """
    Return every address `host` resolves to, or the literal address itself.

    Raises `BlockedTargetError` when the name cannot be resolved: a target
    that does not resolve cannot be checked, so it is not scanned.
    """

    try:
        ipaddress.ip_address(host)

    except ValueError:
        pass

    else:
        return [host]

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            proto=socket.IPPROTO_TCP,
        )

    except socket.gaierror as exc:
        raise BlockedTargetError(
            f"Could not resolve '{host}'."
        ) from exc

    return [info[4][0] for info in infos]


def host_is_exempt(host: str) -> bool:
    return (
        host in settings.ALLOWED_TARGET_HOSTS
        or settings.ALLOW_PRIVATE_TARGETS
    )


def assert_address_allowed(host: str, address: str) -> None:
    """Reject a single resolved address for `host`."""

    if host_is_exempt(host):
        return

    if _is_internal(ipaddress.ip_address(address)):

        raise BlockedTargetError(
            f"'{host}' resolves to the internal address {address}. "
            "Set SECGUARD_ALLOW_PRIVATE_TARGETS=1 or add the host to "
            "SECGUARD_ALLOWED_TARGET_HOSTS to scan it deliberately."
        )


def assert_target_allowed(url: str) -> None:
    """
    Reject targets that are not safe to scan.

    Only http(s) URLs pointing at a public address are allowed. Internal
    addresses (loopback, RFC1918, link-local, reserved) are refused unless
    `SECGUARD_ALLOW_PRIVATE_TARGETS` is set or the hostname is listed in
    `SECGUARD_ALLOWED_TARGET_HOSTS`.
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise BlockedTargetError(
            "Only http:// and https:// targets can be scanned."
        )

    host = (parsed.hostname or "").lower()

    if not host:
        raise BlockedTargetError("The target URL has no host.")

    if host_is_exempt(host):
        return

    for address in resolve_addresses(host):
        assert_address_allowed(host, address)


def unwrap_blocked(exc: BaseException) -> BlockedTargetError | None:
    """
    Find a `BlockedTargetError` inside a wrapping transport error.

    A connection refused at connect time reaches the caller as a
    `requests.ConnectionError` carrying the original error in its args,
    which would otherwise be reported as an unreachable target.
    """

    seen: set[int] = set()
    queue: list[BaseException] = [exc]

    while queue:
        current = queue.pop()

        if current is None or id(current) in seen:
            continue

        seen.add(id(current))

        if isinstance(current, BlockedTargetError):
            return current

        for arg in current.args:

            # urllib3 packs the original error into a tuple argument.
            candidates = arg if isinstance(arg, tuple) else (arg,)

            queue.extend(
                candidate
                for candidate in candidates
                if isinstance(candidate, BaseException)
            )

        queue.extend(
            candidate
            for candidate in (current.__cause__, current.__context__)
            if candidate is not None
        )

    return None


def guard_response(response, *args, **kwargs) -> None:
    """
    `requests` response hook re-checking every hop of a request.

    Redirects are followed by `requests` itself, so without this a public
    target could bounce the scanner onto an internal address.
    """

    del args, kwargs

    assert_target_allowed(response.url)
