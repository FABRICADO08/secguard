from backend.discovery import api_discovery


def test_paths_are_not_probed_when_disabled():
    results = api_discovery.discover_common_api_paths(
        "https://app.test",
        probe_paths=False,
    )

    assert len(results) == len(api_discovery.COMMON_API_PATHS)
    assert all(result["probed"] is False for result in results)
    assert all(result["state"] == "not-probed" for result in results)


def test_probe_results_are_classified(monkeypatch):
    statuses = {
        "/api": 200,
        "/graphql": 403,
        "/odata": 404,
    }

    def fake_probe(url, session=None, **kwargs):
        status = next(
            (
                value
                for path, value in statuses.items()
                if url.endswith(path)
            ),
            404,
        )

        return {
            "url": url,
            "status_code": status,
            "content_type": "application/json",
            "content_length": 10,
            "final_url": url,
            "body_preview": "{}",
        }

    monkeypatch.setattr(api_discovery, "probe", fake_probe)

    results = {
        result["path"]: result
        for result in api_discovery.discover_common_api_paths(
            "https://app.test"
        )
    }

    assert results["/api"]["state"] == "accessible"
    assert results["/api"]["type"] == "api"
    assert results["/graphql"]["state"] == "protected"
    assert results["/odata"]["state"] == "absent"
    assert results["/swagger.json"]["documentation"] is True
    assert results["/api"]["documentation"] is False
