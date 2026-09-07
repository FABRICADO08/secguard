from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import jsonify, request

from backend.config import settings


class RateLimiter:
    """
    In-process fixed-window limiter keyed by caller.

    Sufficient for the single-process deployment this ships as; a shared
    store would be needed once the API runs behind more than one worker.
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


def rate_limited(view: Callable[..., Any]) -> Callable[..., Any]:

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):

        retry_after = limiter.check(
            f"{view.__name__}:{request.remote_addr or 'unknown'}",
            settings.RATE_LIMIT_REQUESTS,
            settings.RATE_LIMIT_WINDOW_SECONDS,
        )

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
