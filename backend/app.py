from __future__ import annotations

import json
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
)

from backend.discovery.api_discovery import (
    discover_common_api_paths,
)
from backend.discovery.crawler import (
    crawl,
)
from backend.discovery.endpoints import (
    discover_endpoints,
)
from backend.discovery.fingerprint import (
    TargetUnreachableError,
    fetch_application,
)
from backend.discovery.technology import (
    detect_technologies,
)
from backend.model.application import (
    Application,
)
from backend.model.normalized import (
    model_statistics,
)
from backend.platforms.mendix.findings import (
    RULE_CATALOGUE as MENDIX_RULE_CATALOGUE,
)
from backend.platforms.mendix.service import (
    analyze_model,
)
from backend.recommendations import (
    build_recommendations,
)
from backend.risk.scoring import (
    summarize,
)
from backend.rules.base import (
    ScanContext,
)
from backend.rules.engine import (
    analyze,
    default_rules,
)
from backend.scanners.configuration import (
    scan_exposed_paths,
)
from backend.storage.findings import (
    load_findings,
    save_findings,
)
from backend.storage.scans import (
    application_exists,
    list_applications,
    load_application,
    save_application,
)

ROOT = (
    Path(__file__)
    .resolve()
    .parent.parent
)

MAX_MODEL_BYTES = 25 * 1024 * 1024

FRONTEND = ROOT / "frontend"


app = Flask(
    __name__
)


# ============================================================
# Frontend
# ============================================================

@app.get("/")
def index():

    return send_from_directory(
        FRONTEND,
        "index.html",
    )


@app.get("/<path:path>")
def frontend_files(path):

    file_path = FRONTEND / path

    if file_path.is_file():

        return send_from_directory(
            FRONTEND,
            path,
        )

    return jsonify(
        {
            "error":
                "Frontend resource not found."
        }
    ), 404


# ============================================================
# Health
# ============================================================

@app.get("/api/health")
def health():

    return jsonify(
        {
            "status":
                "ok",

            "service":
                "Application Security Platform",

            "version":
                "0.2.0",
        }
    )


# ============================================================
# Start discovery
# ============================================================

@app.post("/api/discover")
def discover():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    url = str(
        data.get(
            "url",
            "",
        )
        or ""
    ).strip()

    if not url:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Application URL is required.",
            }
        ), 400

    try:

        # ----------------------------------------------------
        # Initial HTTP discovery
        # ----------------------------------------------------

        response = fetch_application(
            url
        )

        # ----------------------------------------------------
        # Technology detection
        # ----------------------------------------------------

        technologies = detect_technologies(
            response
        )

        # ----------------------------------------------------
        # Same-origin crawl
        # ----------------------------------------------------

        crawl_result = crawl(
            response["final_url"],
            max_pages=20,
        )

        # ----------------------------------------------------
        # Endpoint discovery
        # ----------------------------------------------------

        endpoints = discover_endpoints(
            crawl_result["links"],
            crawl_result["forms"],
        )

        # ----------------------------------------------------
        # Potential API discovery
        # ----------------------------------------------------

        potential_api_paths = (
            discover_common_api_paths(
                response["final_url"]
            )
        )

        # ----------------------------------------------------
        # Exposed sensitive files
        # ----------------------------------------------------

        exposed_paths = scan_exposed_paths(
            response["final_url"]
        )

        # ----------------------------------------------------
        # Platform detection
        # ----------------------------------------------------

        mendix_detected = any(
            technology["name"] == "Mendix"
            for technology
            in technologies
        )

        platform = (
            "Mendix"
            if mendix_detected
            else "Unknown"
        )

        # ----------------------------------------------------
        # Create persistent application
        # ----------------------------------------------------

        application = Application.create(
            requested_url=
                response[
                    "requested_url"
                ],

            final_url=
                response[
                    "final_url"
                ],
        )

        application.set_platform(
            platform
        )

        application.status_code = (
            response["status_code"]
        )

        application.response_time_ms = (
            response["response_time_ms"]
        )

        application.technologies = (
            technologies
        )

        application.attack_surface = {
            "pages":
                crawl_result[
                    "pages"
                ],

            "links":
                crawl_result[
                    "links"
                ],

            "forms":
                crawl_result[
                    "forms"
                ],

            "scripts":
                crawl_result[
                    "scripts"
                ],

            "endpoints":
                endpoints,

            "potential_api_paths":
                potential_api_paths,

            "exposed_paths":
                exposed_paths,

            "pages_scanned":
                crawl_result[
                    "pages_scanned"
                ],
        }

        # ----------------------------------------------------
        # Security analysis
        # ----------------------------------------------------

        analysis = analyze(
            ScanContext(
                application_id=
                    application.id,

                requested_url=
                    application.requested_url,

                final_url=
                    application.final_url,

                platform=
                    platform,

                response=
                    response,

                technologies=
                    technologies,

                attack_surface=
                    application.attack_surface,
            )
        )

        findings = analysis["findings"]

        application.security = {
            **summarize(findings),

            "findings":
                findings,

            "recommendations":
                build_recommendations(findings),

            "rules_evaluated":
                analysis["rules_evaluated"],

            "rule_errors":
                analysis["rule_errors"],
        }

        application.status = "analyzed"

        application.update_timestamp()

        # ----------------------------------------------------
        # Save
        # ----------------------------------------------------

        save_application(
            application.to_dict()
        )

        save_findings(
            application.id,
            findings,
        )

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return jsonify(
            {
                "success":
                    True,

                "application_id":
                    application.id,

                "application":
                    application.to_dict(),
            }
        )

    except ValueError as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    str(exc),
            }
        ), 400

    except TargetUnreachableError as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    str(exc),

                "reason":
                    "unreachable",
            }
        ), 502

    except Exception as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Application discovery failed.",

                "details":
                    str(exc),
            }
        ), 500


# ============================================================
# Mendix model analysis
# ============================================================

def _model_name(value: str) -> str:
    """
    Reduce an uploaded model name to a safe display label.

    Only the file name is kept, control characters and markup are
    dropped, and the result is truncated.
    """

    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]

    name = "".join(
        character
        for character in name
        if character.isprintable()
        and character not in "<>\"'&"
    ).strip()

    return name[:128] or "mendix-model.json"


def _read_model_upload() -> tuple[dict, str]:
    """
    Accept a Mendix model as a multipart upload or a JSON body.

    Returns the decoded model document and the name to display for it.
    """

    if (request.content_length or 0) > MAX_MODEL_BYTES:

        raise ValueError(
            "Mendix model exceeds the "
            f"{MAX_MODEL_BYTES // (1024 * 1024)} MB upload limit."
        )

    upload = request.files.get("model")

    if upload is not None:

        raw = upload.read(
            MAX_MODEL_BYTES + 1
        )

        if len(raw) > MAX_MODEL_BYTES:

            raise ValueError(
                "Mendix model exceeds the "
                f"{MAX_MODEL_BYTES // (1024 * 1024)} MB upload limit."
            )

        if not raw.strip():

            raise ValueError(
                "Uploaded Mendix model file is empty."
            )

        try:

            document = json.loads(
                raw.decode("utf-8")
            )

        except (UnicodeDecodeError, json.JSONDecodeError) as exc:

            raise ValueError(
                f"Uploaded Mendix model is not valid JSON: {exc}"
            ) from exc

        return document, _model_name(
            upload.filename
        )

    body = request.get_json(
        silent=True
    )

    if not isinstance(body, dict):

        raise ValueError(
            "Provide a Mendix model as a 'model' file upload or a "
            "JSON body."
        )

    document = body.get(
        "model",
        body,
    )

    return document, _model_name(
        body.get(
            "name",
            "",
        )
    )


@app.post("/api/mendix/analyze")
def analyze_mendix_model():

    try:

        document, name = _read_model_upload()

        result = analyze_model(
            document
        )

    except ValueError as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    str(exc),
            }
        ), 400

    except Exception as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Mendix model analysis failed.",

                "details":
                    str(exc),
            }
        ), 500

    findings = result["findings"]

    application = Application.create(
        requested_url=
            f"mendix-model://{name}",

        final_url=
            f"mendix-model://{name}",

        name=name,
    )

    application.set_platform(
        "Mendix"
    )

    application.model = result["model"]

    application.security = {
        **summarize(findings),

        "findings":
            findings,

        "recommendations":
            build_recommendations(findings),

        "rules_evaluated":
            len(MENDIX_RULE_CATALOGUE),

        "rule_errors":
            [],
    }

    application.status = "analyzed"

    application.update_timestamp()

    save_application(
        application.to_dict()
    )

    save_findings(
        application.id,
        findings,
    )

    return jsonify(
        {
            "success":
                True,

            "application_id":
                application.id,

            "application":
                application.to_dict(),

            "model_statistics":
                model_statistics(
                    application.model
                ),
        }
    )


# ============================================================
# Application list
# ============================================================

@app.get("/api/applications")
def applications():

    return jsonify(
        {
            "success":
                True,

            "applications":
                list_applications(),
        }
    )


# ============================================================
# Get application
# ============================================================

@app.get(
    "/api/applications/<application_id>"
)
def get_application(
    application_id: str,
):

    if not application_exists(
        application_id
    ):

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Application not found.",
            }
        ), 404

    try:

        application = load_application(
            application_id
        )

        return jsonify(
            {
                "success":
                    True,

                "application":
                    application,

                "model_statistics":
                    model_statistics(
                        application.get(
                            "model",
                            {},
                        )
                    ),
            }
        )

    except Exception as exc:

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Could not load application.",

                "details":
                    str(exc),
            }
        ), 500


# ============================================================
# Findings
# ============================================================

@app.get(
    "/api/applications/<application_id>/findings"
)
def application_findings(
    application_id: str,
):

    if not application_exists(
        application_id
    ):

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Application not found.",
            }
        ), 404

    findings = load_findings(
        application_id
    )

    filters = {
        key: str(
            request.args.get(key)
        ).lower()
        for key in (
            "severity",
            "category",
            "platform",
            "rule_id",
        )
        if request.args.get(key)
    }

    for key, value in filters.items():

        findings = [
            finding
            for finding in findings
            if str(
                finding.get(key, "")
            ).lower() == value
        ]

    return jsonify(
        {
            "success":
                True,

            "application_id":
                application_id,

            "filters":
                filters,

            "summary":
                summarize(findings),

            "findings":
                findings,
        }
    )


@app.get(
    "/api/applications/<application_id>"
    "/findings/<finding_id>"
)
def application_finding(
    application_id: str,
    finding_id: str,
):

    if not application_exists(
        application_id
    ):

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Application not found.",
            }
        ), 404

    for finding in load_findings(
        application_id
    ):

        if finding.get("id") == finding_id:

            return jsonify(
                {
                    "success":
                        True,

                    "finding":
                        finding,
                }
            )

    return jsonify(
        {
            "success":
                False,

            "error":
                "Finding not found.",
        }
    ), 404


# ============================================================
# Rule catalogue
# ============================================================

@app.get("/api/rules")
def rules_catalogue():

    return jsonify(
        {
            "success":
                True,

            "rules": [
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "category": rule.category,
                    "confidence": rule.confidence,
                    "platform": rule.platform,
                    "cwe": rule.cwe,
                    "owasp": rule.owasp,
                    "description": rule.description,
                    "recommendation": rule.recommendation,
                }
                for rule in default_rules()
            ],
        }
    )


# ============================================================
# Development server
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=True,
    )