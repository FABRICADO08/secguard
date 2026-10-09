"""HTTP routes for Mendix and OutSystems model analysis."""

import json

from flask import jsonify, request

from backend.model.application import Application
from backend.model.normalized import platform_model_statistics
from backend.platforms.errors import EmptyModelError
from backend.platforms.mendix.findings import RULE_CATALOGUE as MENDIX_RULE_CATALOGUE
from backend.platforms.mendix.service import EMPTY_MODEL as MENDIX_EMPTY_MODEL
from backend.platforms.outsystems.findings import (
    RULE_CATALOGUE as OUTSYSTEMS_RULE_CATALOGUE,
)
from backend.platforms.outsystems.service import EMPTY_MODEL as OUTSYSTEMS_EMPTY_MODEL
from backend.platforms.outsystems.service import analyze_model as analyze_outsystems_model
from backend.recommendations import build_recommendations
from backend.risk.scoring import summarize
from backend.security.auth import require_api_token
from backend.security.rate_limit import rate_limited
from backend.storage.findings import save_findings
from backend.storage.scans import save_application


def _model_name(value: str, fallback: str = "model.json") -> str:
    """Reduce an uploaded name to a safe, printable display label."""
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(
        character
        for character in name
        if character.isprintable() and character not in "<>\"'&"
    ).strip()
    return name[:128] or fallback


def _read_uploaded_model(upload, platform, fallback, too_large, max_bytes):
    name = _model_name(upload.filename, fallback)
    raw = upload.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return {}, name, too_large
    if not raw.strip():
        return {}, name, f"Uploaded {platform} model file is empty."
    try:
        return json.loads(raw.decode("utf-8")), name, ""
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, name, f"Uploaded {platform} model is not valid JSON."


def _read_json_model_body(body, platform, fallback):
    if not isinstance(body, dict):
        return {}, fallback, (
            f"Provide a {platform} model as a 'model' file upload or a JSON body."
        )
    document = body.get("model", body)
    name = _model_name(body.get("name", ""), fallback)
    return document, name, ""


def _read_model_upload(platform, max_bytes):
    """Read a model from a bounded multipart upload or JSON body."""
    fallback = f"{platform.lower()}-model.json"
    too_large = (
        f"{platform} model exceeds the {max_bytes // (1024 * 1024)} MB upload limit."
    )
    if (request.content_length or 0) > max_bytes:
        return {}, fallback, too_large
    upload = request.files.get("model")
    if upload is None:
        document, name, problem = _read_json_model_body(
            request.get_json(silent=True), platform, fallback
        )
    else:
        document, name, problem = _read_uploaded_model(
            upload, platform, fallback, too_large, max_bytes
        )
    if problem:
        return {}, name, problem
    if not isinstance(document, dict):
        return {}, name, f"{platform} model JSON root must be an object."
    return document, name, ""


def _model_error(message, status):
    return jsonify({"success": False, "error": message}), status


def _analyze_platform_model(app, compatibility, platform, analyzer, empty_model, catalogue):
    max_bytes = compatibility.MAX_MODEL_BYTES
    document, name, problem = _read_model_upload(platform, max_bytes)
    if problem:
        return _model_error(problem, 400)
    try:
        result = analyzer(document)
    except EmptyModelError:
        return _model_error(empty_model, 400)
    except ValueError:
        app.logger.exception("Invalid %s model", platform)
        return _model_error(f"The {platform} model could not be read.", 400)
    except Exception:
        app.logger.exception("%s model analysis failed", platform)
        return _model_error(f"{platform} model analysis failed.", 500)

    findings = result["findings"]
    application = Application.create(
        requested_url=f"{platform.lower()}-model://{name}",
        final_url=f"{platform.lower()}-model://{name}",
        name=name,
    )
    application.set_platform(platform)
    application.model = result["model"]
    application.security = {
        **summarize(findings),
        "findings": findings,
        "recommendations": build_recommendations(findings),
        "rules_evaluated": len(catalogue),
        "rule_errors": [],
    }
    application.status = "analyzed"
    application.update_timestamp()
    save_application(application.to_dict())
    save_findings(application.id, findings)
    return jsonify(
        {
            "success": True,
            "application_id": application.id,
            "application": application.to_dict(),
            "model_statistics": platform_model_statistics(
                platform, application.model
            ),
        }
    )


def register_routes(app, compatibility):
    @app.post("/api/mendix/analyze")
    @require_api_token
    @rate_limited
    def analyze_mendix_model():
        """Analyze and persist an uploaded Mendix model."""
        return _analyze_platform_model(
            app,
            compatibility,
            "Mendix",
            compatibility.analyze_model,
            MENDIX_EMPTY_MODEL,
            MENDIX_RULE_CATALOGUE,
        )

    @app.post("/api/outsystems/analyze")
    @require_api_token
    @rate_limited
    def analyze_outsystems():
        """Analyze and persist an uploaded OutSystems model."""
        return _analyze_platform_model(
            app,
            compatibility,
            "OutSystems",
            analyze_outsystems_model,
            OUTSYSTEMS_EMPTY_MODEL,
            OUTSYSTEMS_RULE_CATALOGUE,
        )
