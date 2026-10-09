import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from backend.config import settings
from backend.security import rate_limit


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create an API test client backed by isolated file storage."""
    from backend import app as app_module
    from backend.storage import scans

    monkeypatch.setattr(scans, "APPLICATIONS_DIR", tmp_path / "applications")
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def post_model_upload(client, endpoint, document, filename):
    """Post a model document as the named multipart upload."""
    import io
    import json

    return client.post(
        endpoint,
        data={
            "model": (
                io.BytesIO(json.dumps(document).encode("utf-8")),
                filename,
            )
        },
        content_type="multipart/form-data",
    )


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
