from backend.scanners import configuration


def fake_probe_factory(responses, default):
    def fake_probe(url, session=None, **kwargs):
        for path, response in responses.items():
            if url.endswith(path):
                return {"url": url, **response}

        return {"url": url, **default}

    return fake_probe


NOT_FOUND = {
    "reachable": True,
    "status_code": 404,
    "content_type": "text/html",
    "content_length": 500,
    "body_preview": "not found",
}

SOFT_404 = {
    "reachable": True,
    "status_code": 200,
    "content_type": "text/html",
    "content_length": 4000,
    "body_preview": "<html>welcome</html>",
}


def test_exposed_env_file_is_reported(monkeypatch):
    monkeypatch.setattr(
        configuration,
        "probe",
        fake_probe_factory(
            {
                "/.env": {
                    "reachable": True,
                    "status_code": 200,
                    "content_type": "text/plain",
                    "content_length": 120,
                    "body_preview": "DB_PASSWORD=hunter2\nAPI_KEY=abc",
                }
            },
            NOT_FOUND,
        ),
    )

    exposures = configuration.scan_exposed_paths("https://app.test")

    assert [exposure["path"] for exposure in exposures] == ["/.env"]
    assert exposures[0]["severity"] == "critical"
    assert exposures[0]["confidence"] == "confirmed"


def test_soft_404_server_reports_nothing(monkeypatch):
    monkeypatch.setattr(
        configuration,
        "probe",
        fake_probe_factory({}, SOFT_404),
    )

    assert configuration.scan_exposed_paths("https://app.test") == []


def test_signature_mismatch_is_not_reported(monkeypatch):
    monkeypatch.setattr(
        configuration,
        "probe",
        fake_probe_factory(
            {
                "/.git/config": {
                    "reachable": True,
                    "status_code": 200,
                    "content_type": "text/html",
                    "content_length": 90,
                    "body_preview": "<html>login</html>",
                }
            },
            NOT_FOUND,
        ),
    )

    assert configuration.scan_exposed_paths("https://app.test") == []


def test_unreachable_target_reports_nothing(monkeypatch):
    monkeypatch.setattr(
        configuration,
        "probe",
        fake_probe_factory(
            {},
            {
                "reachable": False,
                "status_code": None,
                "content_type": "",
                "content_length": 0,
                "body_preview": "",
                "error": "connection refused",
            },
        ),
    )

    assert configuration.scan_exposed_paths("https://app.test") == []
