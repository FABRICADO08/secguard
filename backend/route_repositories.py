"""HTTP routes for repository scans, health, and GitHub workflow actions."""

from flask import jsonify, request

from backend.config import settings
from backend.repository.ingest import application_from_report
from backend.repository.sbom import cyclonedx, spdx
from backend.security import github_auth
from backend.security.auth import request_is_authorized, require_api_token
from backend.security.rate_limit import rate_limited
from backend.storage import application_names
from backend.storage.findings import save_findings
from backend.storage.scans import (
    application_exists,
    list_applications,
    load_application,
    save_application,
)

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


def _latest_repository_scans() -> dict[str, dict]:
    """Return the most recently updated repository scan per repository."""
    latest = {}
    for application in list_applications():
        if application.get("platform") != "Repository":
            continue
        key = github_auth.repository_name(application).lower()
        if key and str(application.get("updated_at") or "") >= str(
            (latest.get(key) or {}).get("updated_at") or ""
        ):
            latest[key] = application
    return latest


def _application_name(repository: str, application: dict | None) -> str:
    """Resolve the display name configured for a repository application."""
    stored = str((application or {}).get("name") or "")
    if stored.lower() == repository.lower():
        stored = ""
    return (
        application_names.name_for(repository)
        or stored
        or repository.rsplit("/", 1)[-1]
    )


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
        save_application(application.to_dict())
        save_findings(application.id, findings)
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
            ]
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
