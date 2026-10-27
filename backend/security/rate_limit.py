from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import jsonify, request

from backend.config import settings
from backend.storage import db

LOG = logging.getLogger(__name__)


class RateLimiter:
    """
    In-process fixed-window limiter keyed by caller.

    Used without Postgres, where only one worker may run; with Postgres the
    shared limiter below keeps one count across workers and instances.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float, window: int) -> None:
        """
        Drop callers whose hits have all expired.

        Without this every source address ever seen keeps an entry, so a
        long-running instance grows with the number of distinct clients.
        """

        if now - self._last_sweep < window:
            return

        self._last_sweep = now

        for key, hits in list(self._hits.items()):

            while hits and now - hits[0] >= window:
                hits.popleft()

            if not hits:
                del self._hits[key]

    def check(
        self,
        key: str,
        limit: int,
        window: int,
    ) -> float | None:
        """
        Record a hit for `key`.

        Returns None when the call is allowed, otherwise the number of
        seconds until the caller may retry.
        """

        if limit <= 0 or window <= 0:
            return None

        now = time.monotonic()

        with self._lock:
            self._sweep(now, window)

            hits = self._hits[key]

            while hits and now - hits[0] >= window:
                hits.popleft()

            if len(hits) >= limit:
                return window - (now - hits[0])

            hits.append(now)

        return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self._last_sweep = time.monotonic()

    def tracked_clients(self) -> int:
        with self._lock:
            return len(self._hits)


limiter = RateLimiter()


def _init_schema(connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                window_start DOUBLE PRECISION NOT NULL,
                hits INTEGER NOT NULL
            )
            """
        )


# A request from an older window (a skewed clock, or one that straddled the
# boundary) counts against the newer window instead of resetting it, and a
# request over the limit updates nothing, so it returns no row.
_COUNT_HIT = """
    INSERT INTO rate_limits (key, window_start, hits) VALUES (%s, %s, 1)
    ON CONFLICT (key) DO UPDATE SET
        hits = CASE WHEN EXCLUDED.window_start > rate_limits.window_start
                    THEN 1 ELSE rate_limits.hits + 1 END,
        window_start = GREATEST(rate_limits.window_start, EXCLUDED.window_start)
    WHERE EXCLUDED.window_start > rate_limits.window_start OR rate_limits.hits < %s
    RETURNING hits
"""


class PostgresRateLimiter:
    """
    Fixed-window counters in Postgres, shared by every worker and instance.

    The upsert counts the hit and reads the total in one statement, so
    concurrent requests cannot both slip under the limit. Once a caller is
    refused, this process refuses it from memory until the window ends, so
    a flood of rejected requests does not reach the database.
    """

    def __init__(self) -> None:
        self._last_sweep = 0.0
        self._blocked: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> float | None:
        if limit <= 0 or window <= 0:
            return None

        now = time.time()
        window_start = float(int(now // window) * window)

        with self._lock:
            blocked_until = self._blocked.get(key, 0.0)
            if blocked_until > now:
                return blocked_until - now

            sweep = now - self._last_sweep >= window
            if sweep:
                self._last_sweep = now
                self._blocked = {name: until for name, until in self._blocked.items() if until > now}

        with db._connection(init=_init_schema) as connection, connection.cursor() as cursor:
            cursor.execute(_COUNT_HIT, (key, window_start, limit))
            counted = cursor.fetchone() is not None

            if sweep:
                cursor.execute("DELETE FROM rate_limits WHERE window_start < %s", (window_start,))

        if counted:
            return None

        with self._lock:
            self._blocked[key] = window_start + window

        return window_start + window - now


shared_limiter = PostgresRateLimiter()


def _check(key: str) -> float | None:
    limit, window = settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW_SECONDS

    if db.use_database():
        try:
            return shared_limiter.check(key, limit, window)
        except Exception as error:  # noqa: BLE001 - an outage must not take the API down with it
            LOG.warning("Shared rate limit unavailable, counting in process (%s)", type(error).__name__)

    return limiter.check(key, limit, window)


def rate_limited(view: Callable[..., Any]) -> Callable[..., Any]:

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):

        retry_after = _check(f"{view.__name__}:{request.remote_addr or 'unknown'}")

        if retry_after is not None:

            seconds = max(1, int(retry_after) + 1)

            response = jsonify(
                {
                    "success":
                        False,

                    "error":
                        "Too many requests. Retry in "
                        f"{seconds} seconds.",

                    "reason":
                        "rate_limited",
                }
            )

            response.headers["Retry-After"] = str(seconds)

            return response, 429

        return view(*args, **kwargs)

    return wrapper
