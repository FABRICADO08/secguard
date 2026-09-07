from __future__ import annotations

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager

from backend.security.targets import assert_address_allowed


def _assert_socket_allowed(host: str, sock) -> None:
    peer = sock.getpeername()[0]

    try:
        assert_address_allowed(
            (host or "").lower(),
            peer,
        )

    except Exception:
        sock.close()

        raise


class _GuardedHTTPConnection(HTTPConnection):
    """
    Checks the address actually connected to, not the one looked up
    earlier, so a name that resolves differently on the second lookup
    (DNS rebinding) cannot reach an internal service.
    """

    def _new_conn(self):
        sock = super()._new_conn()

        _assert_socket_allowed(self.host, sock)

        return sock


class _GuardedHTTPSConnection(HTTPSConnection):

    def _new_conn(self):
        sock = super()._new_conn()

        _assert_socket_allowed(self.host, sock)

        return sock


class _GuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedPoolManager(PoolManager):

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pool_classes_by_scheme = {
            "http": _GuardedHTTPConnectionPool,
            "https": _GuardedHTTPSConnectionPool,
        }


class GuardedAdapter(HTTPAdapter):
    """Transport adapter enforcing the target policy at connect time."""

    def init_poolmanager(
        self,
        connections,
        maxsize,
        block=False,
        **pool_kwargs,
    ) -> None:

        self.poolmanager = _GuardedPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )
