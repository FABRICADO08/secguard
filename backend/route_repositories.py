"""HTTP routes for repository scans, health, and GitHub workflow actions."""

from flask import jsonify, request

from backend.config import settings
from backend.notifications import alerts
from backend.portfolio.applications import application_name as _application_name
from backend.portfolio.applications import (
    latest_repository_scans as _latest_repository_scans,
)
from backend.portfolio.objectives import evaluate
from backend.portfolio.teams import teams_for
from backend.repository.ingest import application_from_report
from backend.repository.sbom import cyclonedx, spdx
from backend.security import github_auth
from backend.security.auth import request_is_authorized, require_api_token
from backend.security.rate_limit import rate_limited
from backend.storage import application_names
from backend.storage import objectives as objective_store
from backend.storage import teams as team_store
from backend.storage.findings import save_findings
from backend.storage.scans import (
    application_exists,
    list_applications,
    load_application,
    save_application,
)
from backend.tickets import sync as ticket_sync


def _repository_report(application_id: str) -> dict | None:
    """Load a repository report and its stored findings, if available."""
    if not application_exists(application_id):
        return None
    application = load_application(application_id)
    report = application.get("repository") or {}
    if not report:
        return None
    return {
        **report,
        "findings": application.get("security", {}).get("findings", []),
    }


def _scan_summary(application: dict | None) -> dict | None:
    """Select the fields used for a repository's latest-scan summary."""
    if not application:
        return None
    return {
        key: application.get(key)
        for key in (
            "id",
            "updated_at",
            "health",
            "maintainability",
            "severity_counts",
            "total_findings",
            "risk_grade",
        )
    }


def _writable_repository(user, owner, name, sign_in_error, access_error):
    """Find a repository and return an authorization error when needed."""
    if user is None:
        return None, (jsonify({"success": False, "error": sign_in_error}), 401)
    repository = user.repositories.get(f"{owner}/{name}".lower())
    if repository is None:
        return None, (
            jsonify({"success": False, "error": "Application not found."}),
            404,
        )
    if not repository["can_trigger"]:
        return None, (jsonify({"success": False, "error": access_error}), 403)
    return repository, None


def _workflow_response(repository, response):
    """Translate a GitHub workflow-dispatch response into the API contract."""
    actions_url = (
        f"{repository['html_url']}/actions/workflows/{settings.GITHUB_WORKFLOW}"
    )
    if response.status_code == 204:
        return jsonify({"success": True, "actions_url": actions_url}), 202
    if response.status_code == 404:
        return jsonify(
            {
                "success": False,
                "error": (
                    f"The repository has no .github/workflows/{settings.GITHUB_WORKFLOW} "
                    "on its default branch. Add the SecGuard workflow first."
                ),
            }
        ), 409
    return jsonify(
        {
            "success": False,
            "error": f"GitHub refused to start the workflow (HTTP {response.status_code}).",
        }
    ), 502


def _rename_stored_applications(full_name, label):
    """Persist the display name on matching stored repository records."""
    application_names.set_name(full_name, label)
    for summary in list_applications():
        if (
            summary.get("platform") == "Repository"
            and github_auth.repository_name(summary).lower() == full_name.lower()
        ):
            record = load_application(summary["id"])
            record["name"] = label
            save_application(record)


def _previous_findings(key: str) -> list[dict] | None:
    """Findings of the application's latest stored scan, or None before its first scan."""
    previous = _latest_repository_scans().get(key)
    if previous is None:
        return None
    return (load_application(previous["id"]).get("security") or {}).get("findings") or []


def _register_ingest_route(app, compatibility):
    @app.post("/api/repository/scans")
    @require_api_token
    @rate_limited
    def ingest_repository_scan():
        if (request.content_length or 0) > compatibility.MAX_MODEL_BYTES:
            return jsonify(
                {
                    "success": False,
                    "error": "Repository report exceeds the upload limit.",
                }
            ), 413
        try:
            application, findings = application_from_report(
                request.get_json(silent=True)
            )
        except ValueError:
            return jsonify(
                {
                    "success": False,
                    "error": "The upload is not a valid SecGuard repository report. "
                    "Generate it with 'python -m backend.repository scan'.",
                }
            ), 400
        application.update_timestamp()
        key = github_auth.repository_name(application.to_dict()).lower()
        previous = _previous_findings(key) if alerts.enabled() else None
        save_application(application.to_dict())
        save_findings(application.id, findings)
        ticket_sync.sync_in_background(application.to_dict(), findings)
        if alerts.enabled():
            alerts.notify_new_findings(
                _application_name(key, application.to_dict()), application.id, previous, findings
            )
        return jsonify(
            {
                "success": True,
                "application_id": application.id,
                "health": application.repository.get("health"),
                "summary": {
                    key: value
                    for key, value in application.security.items()
                    if key not in ("findings", "recommendations")
                },
            }
        ), 201


def _register_sbom_route(app):
    @app.get("/api/applications/<application_id>/sbom")
    def repository_sbom(application_id: str):
        report = _repository_report(application_id)
        if report is None:
            return jsonify(
                {"success": False, "error": "No scan found for this application."}
            ), 404
        sbom_format = request.args.get("format", "cyclonedx").lower()
        if sbom_format not in ("cyclonedx", "spdx"):
            return jsonify(
                {"success": False, "error": "format must be 'cyclonedx' or 'spdx'."}
            ), 400
        document = cyclonedx(report) if sbom_format == "cyclonedx" else spdx(report)
        name = str(
            (report.get("repository") or {}).get("name") or application_id
        ).replace("/", "_")
        response = jsonify(document)
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{name}.{sbom_format}.json"'
        )
        return response


def _register_quality_route(app):
    @app.get("/api/applications/<application_id>/quality")
    def repository_quality(application_id: str):
        report = _repository_report(application_id)
        if report is None:
            return jsonify(
                {"success": False, "error": "No scan found for this application."}
            ), 404
        return jsonify(
            {
                "success": True,
                "quality": report.get("quality") or {},
                "health": report.get("health") or {},
            }
        )


def _team_granted_items(user, latest: dict[str, dict]) -> list[dict]:
    """Read-only entries for scanned applications the user reaches only through team membership."""
    return [
        {
            "name": github_auth.repository_name(latest[key]) or key,
            "private": None,
            "html_url": "",
            "default_branch": "",
            "description": "",
            "can_trigger": False,
            "can_rename": False,
            "display_name": _application_name(key, latest[key]),
            "latest_scan": _scan_summary(latest[key]),
        }
        for key in sorted(github_auth.readable_keys(user) - set(user.repositories))
        if key in latest
    ]


def _register_repositories_route(app):
    @app.get("/api/repositories")
    def repositories():
        latest = _latest_repository_scans()
        if not github_auth.enabled():
            items = [
                {
                    "name": application.get("repository") or application.get("name"),
                    "private": None,
                    "html_url": "",
                    "default_branch": "",
                    "description": "",
                    "can_trigger": False,
                    "can_rename": True,
                    "display_name": _application_name(key, application),
                    "latest_scan": _scan_summary(application),
                }
                for key, application in latest.items()
            ]
        else:
            user = github_auth.current_user()
            if user is None:
                return jsonify(
                    {
                        "success": False,
                        "error": "Sign in with GitHub to see your applications.",
                    }
                ), 401
            items = [
                {
                    **repository,
                    "can_rename": repository["can_trigger"],
                    "display_name": _application_name(key, latest.get(key)),
                    "latest_scan": _scan_summary(latest.get(key)),
                }
                for key, repository in user.repositories.items()
            ] + _team_granted_items(user, latest)
        objectives = objective_store.load()
        teams = team_store.load()
        for item in items:
            item["teams"] = teams_for(str(item["name"]), teams)
            if item["latest_scan"] is not None:
                item["latest_scan"]["objectives"] = evaluate(objectives, item["latest_scan"])
        items.sort(
            key=lambda item: (
                item["latest_scan"] is None,
                str(item["name"]).lower(),
            )
        )
        return jsonify(
            {
                "success": True,
                "github_enabled": github_auth.enabled(),
                "objectives": objectives,
                "repositories": items,
            }
        )


def _register_refresh_route(app):
    @app.post("/api/repositories/refresh")
    def refresh_repositories():
        user = github_auth.current_user()
        if user is None:
            return jsonify(
                {"success": False, "error": "Sign in with GitHub first."}
            ), 401
        try:
            github_auth.refresh_repositories(user)
        except (github_auth.requests.RequestException, ValueError):
            return jsonify(
                {"success": False, "error": "Could not reach GitHub."}
            ), 502
        return jsonify({"success": True, "repositories": len(user.repositories)})


def _register_scan_route(app):
    @app.post("/api/repositories/<owner>/<name>/scan")
    def trigger_repository_scan(owner: str, name: str):
        user = github_auth.current_user()
        repository, error = _writable_repository(
            user,
            owner,
            name,
            "Sign in with GitHub to start a scan.",
            "Starting a scan needs write access to the application's GitHub repository.",
        )
        if error:
            return error
        try:
            response = github_auth.dispatch_workflow(user, repository)
        except github_auth.requests.RequestException:
            return jsonify(
                {"success": False, "error": "Could not reach GitHub."}
            ), 502
        return _workflow_response(repository, response)


def _register_rename_route(app):
    @app.put("/api/repositories/<owner>/<name>/name")
    def rename_repository_application(owner: str, name: str):
        full_name = f"{owner}/{name}"
        if github_auth.enabled():
            user = github_auth.current_user()
            repository, error = _writable_repository(
                user,
                owner,
                name,
                "Sign in with GitHub to rename an application.",
                "Renaming needs write access to the application's GitHub repository.",
            )
            if error:
                return error
            full_name = repository["name"]
        elif not request_is_authorized():
            return jsonify(
                {
                    "success": False,
                    "error": "Unauthorized. Set SECGUARD_API_TOKEN and send it as 'X-API-Key'.",
                }
            ), 401
        value = (request.get_json(silent=True) or {}).get("name")
        problem = application_names.name_problem(value)
        if problem:
            return jsonify({"success": False, "error": problem}), 400
        label = application_names.normalise(value)
        _rename_stored_applications(full_name, label)
        return jsonify({"success": True, "name": label})


def register_routes(app, compatibility):
    _register_ingest_route(app, compatibility)
    _register_sbom_route(app)
    _register_quality_route(app)
    _register_repositories_route(app)
    _register_refresh_route(app)
    _register_scan_route(app)
    _register_rename_route(app)
