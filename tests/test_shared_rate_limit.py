"""The Postgres rate limiter, driven through a fake connection that applies its upsert."""

from contextlib import contextmanager

import pytest

from backend.config import settings
from backend.security import rate_limit
from backend.storage import db


class FakeDatabase:
    def __init__(self):
        self.rows = {}

    @contextmanager
    def connection(self, init=None):
        yield self

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, sql, params=()):
        if "INSERT INTO rate_limits" in sql:
            key, window_start = params
            previous = self.rows.get(key)
            hits = previous[1] + 1 if previous and previous[0] == window_start else 1
            self.rows[key] = (window_start, hits)
            self._result = (hits,)
        elif "DELETE FROM rate_limits" in sql:
            self.rows = {key: row for key, row in self.rows.items() if row[0] >= params[0]}

    def fetchone(self):
        return self._result


@pytest.fixture
def database(monkeypatch):
    fake = FakeDatabase()
    monkeypatch.setattr(db, "_connection", fake.connection)
    return fake


@pytest.fixture
def clock(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(rate_limit.time, "time", lambda: now[0])
    return now


def test_workers_share_one_count(database, clock):
    first, second = rate_limit.PostgresRateLimiter(), rate_limit.PostgresRateLimiter()

    assert first.check("scan:198.51.100.1", limit=2, window=60) is None
    assert second.check("scan:198.51.100.1", limit=2, window=60) is None
    assert first.check("scan:198.51.100.1", limit=2, window=60) == pytest.approx(20.0)
    assert second.check("scan:198.51.100.2", limit=2, window=60) is None


def test_a_new_window_starts_a_new_count_and_sweeps_old_rows(database, clock):
    limiter = rate_limit.PostgresRateLimiter()
    limiter.check("scan:198.51.100.1", limit=1, window=60)
    assert limiter.check("scan:198.51.100.1", limit=1, window=60) is not None

    clock[0] += 60
    assert limiter.check("scan:198.51.100.2", limit=1, window=60) is None

    assert "scan:198.51.100.1" not in database.rows
    assert limiter.check("scan:198.51.100.1", limit=1, window=60) is None


def test_the_shared_limiter_is_used_with_postgres(database, clock, monkeypatch):
    monkeypatch.setattr(db, "use_database", lambda: True)
    monkeypatch.setattr(settings, "RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 60)

    assert rate_limit._check("scan:198.51.100.1") is None
    assert rate_limit._check("scan:198.51.100.1") is not None
    assert rate_limit.limiter.tracked_clients() == 0


def test_a_database_outage_falls_back_to_in_process_counts(monkeypatch, caplog):
    def unreachable(init=None):
        raise OSError("could not connect password=hunter2")

    monkeypatch.setattr(db, "_connection", unreachable)
    monkeypatch.setattr(db, "use_database", lambda: True)
    monkeypatch.setattr(settings, "RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 60)

    assert rate_limit._check("scan:198.51.100.1") is None
    assert rate_limit._check("scan:198.51.100.1") is not None
    assert "hunter2" not in caplog.text and "OSError" in caplog.text
