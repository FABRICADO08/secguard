import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from backend.config import settings
from backend.security import rate_limit


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Keep the process-wide limiter from leaking between tests."""

    rate_limit.limiter.reset()

    yield

    rate_limit.limiter.reset()


@pytest.fixture
def allow_local_targets(monkeypatch):
    """Authorize the loopback fixture hosts the discovery tests scan."""

    monkeypatch.setattr(
        settings,
        "ALLOWED_TARGET_HOSTS",
        frozenset({"127.0.0.1", "localhost"}),
    )
