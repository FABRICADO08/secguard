from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

from flask import (
    Flask,
    jsonify,
    redirect,
    request,
    send_from_directory,
)
from werkzeug.middleware.proxy_fix import ProxyFix

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
    CertificateRejectedError,
    TargetUnreachableError,
    fetch_application,
    validate_url,
)
from backend.discovery.libraries import (
    detect_libraries,
)
from backend.discovery.reflection import (
    probe_reflection,
)
from backend.discovery.robots import (
    discover_robots_and_sitemaps,
)
from backend.discovery.scripts import (
    analyze_scripts,
)
from backend.discovery.technology import (
    detect_technologies,
)
from backend.discovery.tls import (
    analyze_tls,
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
from backend.platforms.errors import (
    EmptyModelError,
)
from backend.platforms.mendix.service import (
    EMPTY_MODEL as MENDIX_EMPTY_MODEL,
)
from backend.platforms.mendix.service import (
    analyze_model,
)
from backend.platforms.outsystems.findings import (
    RULE_CATALOGUE as OUTSYSTEMS_RULE_CATALOGUE,
)
from backend.platforms.outsystems.service import (
    EMPTY_MODEL as OUTSYSTEMS_EMPTY_MODEL,
)
from backend.platforms.outsystems.service import (
    analyze_model as analyze_outsystems_model,
)
from backend.portfolio.summary import (
    portfolio_summary,
)
from backend.recommendations import (
    build_recommendations,
)
from backend.repository.findings import (
    RULE_CATALOGUE as REPOSITORY_RULE_CATALOGUE,
)
from backend.repository.ingest import (
    application_from_report,
)
from backend.repository.sbom import (
    cyclonedx,
    spdx,
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
from backend.config import settings
from backend.security import github_auth
from backend.security.auth import request_is_authorized, require_api_token
from backend.security.rate_limit import rate_limited
from backend.security.targets import (
    BlockedTargetError,
    assert_target_allowed,
)
from backend.storage import application_names
from backend.storage.findings import (
    load_findings,
    save_findings,
)
from backend.storage.scans import (
    application_exists,
    delete_application,
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

app.secret_key = settings.SECRET_KEY or secrets.token_hex(32)

class _FirstForwardedValue:
    """
    WSGI middleware that takes the first (left-most) value of each
    X-Forwarded-* header, added by the outermost proxy. Use it when the
    number of proxies is unknown (Azure Front Door in front of App Service,
    for example): ProxyFix always counts from the right, so with more hops
    than the configured depth it would hand the scheme and host chosen by
    an inner hop — or by the client — to OAuth redirect derivation. The
    left-most scheme/host can only be influenced by a client when no proxy
    strips them, which is exactly the deployments this flag is for.

    Only wsgi.url_scheme, HTTP_HOST and SERVER_PORT are rewritten; the
    client address is not trusted because rate limiting keys on it.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        proto = environ.get("HTTP_X_FORWARDED_PROTO", "").split(",")[0].strip()

        if proto:
            environ["wsgi.url_scheme"] = proto

        host = environ.get("HTTP_X_FORWARDED_HOST", "").split(",")[0].strip()

        if host:
            environ["HTTP_HOST"] = environ["SERVER_NAME"] = host

        port = environ.get("HTTP_X_FORWARDED_PORT", "").split(",")[0].strip()

        if port:
            environ["SERVER_PORT"] = port

        return self.app(environ, start_response)


# Trust the X-Forwarded-* headers of the proxies in front of SecGuard, so
# URLs derived from a request (for example the GitHub OAuth callback) use
# the scheme and host visitors actually reach.
if settings.TRUST_FIRST_FORWARDED_VALUE:
    app.wsgi_app = _FirstForwardedValue(app.wsgi_app)
elif settings.PROXY_DEPTH > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=settings.PROXY_DEPTH,
        x_proto=settings.PROXY_DEPTH,
        x_host=settings.PROXY_DEPTH,
        x_port=settings.PROXY_DEPTH,
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=settings.SESSION_COOKIE_SECURE,
)

app.register_blueprint(github_auth.blueprint)


@app.before_request
def hide_inaccessible_applications():
    """Treat a repository the signed-in user cannot read as nonexistent."""

    application_id = (request.view_args or {}).get("application_id")

    if not application_id or not application_exists(application_id):
        return None

    if github_auth.can_view(load_application(application_id)):
        return None

    return jsonify(
        {
            "success": False,
            "error": "Application not found.",
        }
    ), 404


# ============================================================
# Frontend
# ============================================================

def _sign_in_gate(page: str):
    """
    With GitHub sign-in configured, pages open only for a signed-in user;
    everyone else is sent to the sign-in page and brought back afterwards.
    """

    if not github_auth.enabled() or not page.endswith(".html"):
        return None

    signed_in = github_auth.current_user() is not None

    if page == github_auth.LOGIN_PAGE:
        if signed_in:
            return redirect(github_auth.DEFAULT_LANDING)

        next_page = github_auth.safe_next(request.args.get("next", ""))

        return redirect(
            "/auth/github/login?" + urlencode({"next": next_page})
        )

    if signed_in:
        return None

    return redirect(
        "/login.html?" + urlencode({"next": request.full_path.rstrip("?")})
    )


@app.get("/")
def index():

    gate = _sign_in_gate("index.html")

    if gate is not None:

        return gate

    return send_from_directory(
        FRONTEND,
        "index.html",
    )


@app.get("/<path:path>")
def frontend_files(path):

    file_path = FRONTEND / path

    gate = _sign_in_gate(path)

    if gate is not None and file_path.is_file():

        return gate

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


BLOCKED_TARGET_MESSAGE = (
    "The target, or a page it redirects to, is not allowed: only public "
    "http(s) addresses can be scanned. Set SECGUARD_ALLOW_PRIVATE_TARGETS=1 "
    "or add the host to SECGUARD_ALLOWED_TARGET_HOSTS to scan it deliberately."
)

CERTIFICATE_REJECTED_MESSAGE = "The server's TLS certificate failed validation."


def _certificate_only_scan(
    url: str,
    error: str,
    rejected_url: str = "",
):
    """
    Record a scan for a target whose certificate failed validation.

    No page can be fetched from such a target, but its certificate is
    exactly what `GEN-TLS-006` and `GEN-TLS-007` report on, so the TLS
    diagnosis is analysed and persisted on its own instead of being
    thrown away with the fetch error.

    The rejected request is the one inspected: a target that redirects
    to another host before the handshake fails would otherwise have a
    healthy first hop described in place of the failing one.
    """

    requested_url = validate_url(url)

    final_url = (
        validate_url(rejected_url)
        if rejected_url
        else requested_url
    )

    # The redirect hop was checked when it was followed; it is checked
    # again here because this handshake is a fresh connection.
    assert_target_allowed(
        final_url
    )

    tls_result = analyze_tls(
        final_url
    )

    response = {
        "requested_url":
            requested_url,

        "final_url":
            final_url,

        "status_code":
            None,

        "https":
            True,

        "headers": {},

        "cookies": [],

        "body":
            "",

        "redirect_chain": [],

        "http_redirect": {
            "tested":
                False,
        },
    }

    application = Application.create(
        requested_url=requested_url,
        final_url=final_url,
    )

    application.set_platform(
        "Generic"
    )

    application.attack_surface = {
        "pages": [],
        "links": [],
        "forms": [],
        "scripts": [],
        "endpoints": [],
        "potential_api_paths": [],
        "exposed_paths": [],
        "pages_scanned": 0,

        "tls":
            tls_result,
    }

    analysis = analyze(
        ScanContext(
            application_id=
                application.id,

            requested_url=
                application.requested_url,

            final_url=
                application.final_url,

            platform=
                "Generic",

            response=
                response,

            technologies=[],

            attack_surface=
                application.attack_surface,

            response_observed=
                False,
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

    application.status = (
        "certificate_rejected"
    )

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

            "partial":
                True,

            "reason":
                "certificate_rejected",

            "error":
                error,

            "application_id":
                application.id,

            "application":
                application.to_dict(),
        }
    )


# ============================================================
# Start discovery
# ============================================================

def _discover_surface(url: str) -> dict:
    assert_target_allowed(url)
    response = fetch_application(url)
    technologies = detect_technologies(response)
    crawl_result = crawl(response["final_url"], max_pages=20)
    endpoints = discover_endpoints(crawl_result["links"], crawl_result["forms"])
    robots_result = discover_robots_and_sitemaps(response["final_url"])
    script_result = analyze_scripts(crawl_result["scripts"], response["final_url"])
    libraries = detect_libraries(
        crawl_result["scripts"],
        response["body"],
        response["headers"],
        extra=script_result["libraries"],
    )
    reflection_result = probe_reflection(
        crawl_result["forms"], crawl_result["links"], response["final_url"]
    )
    return {
        "response": response,
        "technologies": technologies,
        "crawl": crawl_result,
        "endpoints": endpoints,
        "robots": robots_result,
        "scripts": script_result,
        "libraries": libraries,
        "reflection": reflection_result,
        "potential_api_paths": discover_common_api_paths(response["final_url"]),
        "exposed_paths": scan_exposed_paths(response["final_url"]),
        "tls": analyze_tls(response["final_url"]),
    }


def _create_discovered_application(surface: dict) -> tuple[Application, str]:
    response = surface["response"]
    technologies = surface["technologies"]
    crawl_result = surface["crawl"]
    script_result = surface["scripts"]
    detected = {technology["name"] for technology in technologies}
    platform = next(
        (candidate for candidate in ("Mendix", "OutSystems") if candidate in detected),
        "Generic",
    )
    application = Application.create(
        requested_url=response["requested_url"],
        final_url=response["final_url"],
    )
    application.set_platform(platform)
    application.status_code = response["status_code"]
    application.response_time_ms = response["response_time_ms"]
    application.technologies = technologies
    application.attack_surface = {
        "pages": crawl_result["pages"],
        "links": crawl_result["links"],
        "forms": crawl_result["forms"],
        "scripts": crawl_result["scripts"],
        "endpoints": surface["endpoints"],
        "script_endpoints": script_result["endpoints"],
        "script_analysis": {"scripts": script_result["scripts"]},
        "libraries": surface["libraries"],
        "robots": surface["robots"]["robots"],
        "sitemap": surface["robots"]["sitemap"],
        "reflection": surface["reflection"],
        "potential_api_paths": surface["potential_api_paths"],
        "exposed_paths": surface["exposed_paths"],
        "pages_scanned": crawl_result["pages_scanned"],
        "tls": surface["tls"],
    }
    return application, platform


def _analyze_and_save_discovery(
    application: Application, platform: str, response: dict, technologies: list[dict]
) -> dict:
    analysis = analyze(
        ScanContext(
            application_id=application.id,
            requested_url=application.requested_url,
            final_url=application.final_url,
            platform=platform,
            response=response,
            technologies=technologies,
            attack_surface=application.attack_surface,
        )
    )
    findings = analysis["findings"]
    application.security = {
        **summarize(findings),
        "findings": findings,
        "recommendations": build_recommendations(findings),
        "rules_evaluated": analysis["rules_evaluated"],
        "rule_errors": analysis["rule_errors"],
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
        }
    )


def _perform_discovery(url: str):
    surface = _discover_surface(url)
    application, platform = _create_discovered_application(surface)
    return _analyze_and_save_discovery(
        application,
        platform,
        surface["response"],
        surface["technologies"],
    )


def _discovery_error_response(url: str, error: Exception):
    if isinstance(error, BlockedTargetError):
        return jsonify(
            {
                "success": False,
                "error": BLOCKED_TARGET_MESSAGE,
                "reason": "blocked_target",
            }
        ), 403
    if isinstance(error, ValueError):
        return jsonify(
            {
                "success": False,
                "error": "Enter a valid http:// or https:// application URL.",
            }
        ), 400
    if isinstance(error, CertificateRejectedError):
        try:
            return _certificate_only_scan(
                url, CERTIFICATE_REJECTED_MESSAGE, error.url
            )
        except BlockedTargetError:
            return jsonify(
                {
                    "success": False,
                    "error": BLOCKED_TARGET_MESSAGE,
                    "reason": "blocked_target",
                }
            ), 403
    if isinstance(error, TargetUnreachableError):
        return jsonify(
            {
                "success": False,
                "error": f"Could not connect to {url}.",
                "reason": "unreachable",
            }
        ), 502
    app.logger.exception("Application discovery failed.")
    return jsonify(
        {"success": False, "error": "Application discovery failed."}
    ), 500


@app.post("/api/discover")
@require_api_token
@rate_limited
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
        return _perform_discovery(url)
    except Exception as exc:
        return _discovery_error_response(url, exc)


# ============================================================
# Platform model analysis
# ============================================================

def _model_name(
    value: str,
    fallback: str = "model.json",
) -> str:
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

    return name[:128] or fallback


def _read_model_upload(
    platform: str = "Mendix",
) -> tuple[dict, str, str]:
    """
    Accept a platform model as a multipart upload or a JSON body.

    Returns the decoded model document, the name to display for it and,
    when the upload is unusable, why.
    """

    fallback = f"{platform.lower()}-model.json"
    too_large = (
        f"{platform} model exceeds the "
        f"{MAX_MODEL_BYTES // (1024 * 1024)} MB upload limit."
    )

    if (request.content_length or 0) > MAX_MODEL_BYTES:

        return {}, fallback, too_large

    upload = request.files.get("model")

    if upload is not None:

        name = _model_name(
            upload.filename,
            fallback,
        )

        raw = upload.read(
            MAX_MODEL_BYTES + 1
        )

        if len(raw) > MAX_MODEL_BYTES:

            return {}, name, too_large

        if not raw.strip():

            return {}, name, f"Uploaded {platform} model file is empty."

        try:

            document = json.loads(
                raw.decode("utf-8")
            )

        except (UnicodeDecodeError, json.JSONDecodeError):

            return {}, name, f"Uploaded {platform} model is not valid JSON."

    else:

        body = request.get_json(
            silent=True
        )

        if not isinstance(body, dict):

            return {}, fallback, (
                f"Provide a {platform} model as a 'model' file upload or "
                "a JSON body."
            )

        document = body.get(
            "model",
            body,
        )

        name = _model_name(
            body.get(
                "name",
                "",
            ),
            fallback,
        )

    if not isinstance(document, dict):

        return {}, name, f"{platform} model JSON root must be an object."

    return document, name, ""


def _analyze_upload(
    platform: str,
    analyze,
    empty_model: str,
):
    """
    Read and analyze an uploaded model.

    Returns ``(result, name, None)`` on success, or ``(None, "", response)``
    with the error response to send.
    """

    document, name, problem = _read_model_upload(
        platform
    )

    if problem:

        return None, "", (
            jsonify(
                {
                    "success": False,
                    "error": problem,
                }
            ),
            400,
        )

    try:

        return analyze(document), name, None

    except EmptyModelError:

        return None, "", (
            jsonify(
                {
                    "success": False,
                    "error": empty_model,
                }
            ),
            400,
        )

    except ValueError:

        app.logger.exception("Invalid %s model", platform)

        return None, "", (
            jsonify(
                {
                    "success": False,
                    "error": f"The {platform} model could not be read.",
                }
            ),
            400,
        )

    except Exception:

        app.logger.exception("%s model analysis failed", platform)

        return None, "", (
            jsonify(
                {
                    "success": False,
                    "error": f"{platform} model analysis failed.",
                }
            ),
            500,
        )


@app.post("/api/mendix/analyze")
@require_api_token
@rate_limited
def analyze_mendix_model():

    result, name, error = _analyze_upload(
        "Mendix",
        analyze_model,
        MENDIX_EMPTY_MODEL,
    )

    if error:

        return error

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


def _outsystems_statistics(
    model: dict,
) -> dict[str, int]:

    return {
        key:
            len(model.get(key) or [])
        for key in (
            "modules",
            "entities",
            "screens",
            "rest_methods",
            "consumed_apis",
            "site_properties",
            "queries",
            "roles",
        )
    }


def _platform_model_statistics(
    platform: str,
    model: dict,
) -> dict[str, int]:

    if str(platform or "").lower() == "outsystems":
        return _outsystems_statistics(model)

    return model_statistics(model)


@app.post("/api/outsystems/analyze")
@require_api_token
@rate_limited
def analyze_outsystems():

    result, name, error = _analyze_upload(
        "OutSystems",
        analyze_outsystems_model,
        OUTSYSTEMS_EMPTY_MODEL,
    )

    if error:

        return error

    findings = result["findings"]

    application = Application.create(
        requested_url=
            f"outsystems-model://{name}",

        final_url=
            f"outsystems-model://{name}",

        name=name,
    )

    application.set_platform(
        "OutSystems"
    )

    application.model = result["model"]

    application.security = {
        **summarize(findings),

        "findings":
            findings,

        "recommendations":
            build_recommendations(findings),

        "rules_evaluated":
            len(OUTSYSTEMS_RULE_CATALOGUE),

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
                _outsystems_statistics(
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
                github_auth.visible(
                    list_applications()
                ),
        }
    )


# ============================================================
# Portfolio summary
# ============================================================

@app.get("/api/portfolio/summary")
def portfolio():

    return jsonify(
        {
            "success":
                True,

            **portfolio_summary(
                github_auth.visible(
                    list_applications()
                ),
                load_findings,
            ),
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
                    _platform_model_statistics(
                        application.get(
                            "platform",
                            "",
                        ),
                        application.get(
                            "model",
                            {},
                        ),
                    ),
            }
        )

    except Exception:

        app.logger.exception("Could not load application.")

        return jsonify(
            {
                "success":
                    False,

                "error":
                    "Could not load application.",
            }
        ), 500


# ============================================================
# Delete application
# ============================================================

@app.delete(
    "/api/applications/<application_id>"
)
@require_api_token
def remove_application(
    application_id: str,
):

    if not delete_application(
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

    return jsonify(
        {
            "success":
                True,

            "application_id":
                application_id,
        }
    )


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

def _platform_rules(
    platform: str,
    catalogue: dict,
) -> list[dict]:
    """
    Catalogue entries for a model analyzer.

    Severity and remediation depend on the model element the rule
    matched, so they are reported per finding rather than here.
    """

    return [
        {
            "id": rule_id,
            "title": metadata["title"],
            "severity": "",
            "category": metadata["category"],
            "confidence": metadata["confidence"],
            "platform": platform,
            "cwe": metadata["cwe"],
            "owasp": metadata["owasp"],
            "description": "",
            "recommendation": "",
        }
        for rule_id, metadata in catalogue.items()
    ]


@app.get("/api/rules")
def rules_catalogue():

    rules = [
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
    ]

    rules.extend(
        _platform_rules(
            "Mendix",
            MENDIX_RULE_CATALOGUE,
        )
    )

    rules.extend(
        _platform_rules(
            "OutSystems",
            OUTSYSTEMS_RULE_CATALOGUE,
        )
    )

    rules.extend(
        _platform_rules(
            "Repository",
            {
                rule_id: {**metadata, "confidence": ""}
                for rule_id, metadata in REPOSITORY_RULE_CATALOGUE.items()
            },
        )
    )

    return jsonify(
        {
            "success":
                True,

            "rules": rules,
        }
    )


# ============================================================
# Repository scans
# ============================================================

@app.post("/api/repository/scans")
@require_api_token
@rate_limited
def ingest_repository_scan():
    """Store a report produced by the SecGuard repository scanner."""

    if (request.content_length or 0) > MAX_MODEL_BYTES:

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

    save_application(
        application.to_dict()
    )

    save_findings(
        application.id,
        findings,
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


def _repository_report(
    application_id: str,
) -> dict | None:

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


@app.get("/api/applications/<application_id>/sbom")
def repository_sbom(
    application_id: str,
):

    report = _repository_report(application_id)

    if report is None:

        return jsonify(
            {
                "success": False,
                "error": "No scan found for this application.",
            }
        ), 404

    sbom_format = request.args.get("format", "cyclonedx").lower()

    if sbom_format not in ("cyclonedx", "spdx"):

        return jsonify(
            {
                "success": False,
                "error": "format must be 'cyclonedx' or 'spdx'.",
            }
        ), 400

    document = cyclonedx(report) if sbom_format == "cyclonedx" else spdx(report)

    name = str((report.get("repository") or {}).get("name") or application_id).replace("/", "_")

    response = jsonify(document)

    response.headers["Content-Disposition"] = (
        f'attachment; filename="{name}.{sbom_format}.json"'
    )

    return response


@app.get("/api/applications/<application_id>/quality")
def repository_quality(
    application_id: str,
):

    report = _repository_report(application_id)

    if report is None:

        return jsonify(
            {
                "success": False,
                "error": "No scan found for this application.",
            }
        ), 404

    return jsonify(
        {
            "success": True,
            "quality": report.get("quality") or {},
            "health": report.get("health") or {},
        }
    )


def _latest_repository_scans() -> dict[str, dict]:

    latest: dict[str, dict] = {}

    for application in list_applications():

        if application.get("platform") != "Repository":
            continue

        key = github_auth.repository_name(application).lower()

        if key and str(application.get("updated_at") or "") >= str((latest.get(key) or {}).get("updated_at") or ""):
            latest[key] = application

    return latest


def _application_name(repository: str, application: dict | None) -> str:

    stored = str((application or {}).get("name") or "")

    if stored.lower() == repository.lower():
        stored = ""

    return (
        application_names.name_for(repository)
        or stored
        or repository.rsplit("/", 1)[-1]
    )


def _scan_summary(application: dict | None) -> dict | None:

    if not application:
        return None

    return {
        key: application.get(key)
        for key in ("id", "updated_at", "health", "severity_counts", "total_findings", "risk_grade")
    }


@app.get("/api/repositories")
def repositories():
    """Repositories the user can open, each with its latest scan."""

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


@app.post("/api/repositories/refresh")
def refresh_repositories():

    user = github_auth.current_user()

    if user is None:

        return jsonify(
            {
                "success": False,
                "error": "Sign in with GitHub first.",
            }
        ), 401

    try:
        github_auth.refresh_repositories(user)

    except (github_auth.requests.RequestException, ValueError):

        return jsonify(
            {
                "success": False,
                "error": "Could not reach GitHub.",
            }
        ), 502

    return jsonify(
        {
            "success": True,
            "repositories": len(user.repositories),
        }
    )


@app.post("/api/repositories/<owner>/<name>/scan")
def trigger_repository_scan(
    owner: str,
    name: str,
):
    """Start the repository's SecGuard workflow (the manual "Run workflow")."""

    user = github_auth.current_user()

    if user is None:

        return jsonify(
            {
                "success": False,
                "error": "Sign in with GitHub to start a scan.",
            }
        ), 401

    repository = user.repositories.get(f"{owner}/{name}".lower())

    if repository is None:

        return jsonify(
            {
                "success": False,
                "error": "Application not found.",
            }
        ), 404

    if not repository["can_trigger"]:

        return jsonify(
            {
                "success": False,
                "error": "Starting a scan needs write access to the application's GitHub repository.",
            }
        ), 403

    try:
        response = github_auth.dispatch_workflow(user, repository)

    except github_auth.requests.RequestException:

        return jsonify(
            {
                "success": False,
                "error": "Could not reach GitHub.",
            }
        ), 502

    actions_url = (
        f"{repository['html_url']}/actions/workflows/{settings.GITHUB_WORKFLOW}"
    )

    if response.status_code == 204:

        return jsonify(
            {
                "success": True,
                "actions_url": actions_url,
            }
        ), 202

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


@app.put("/api/repositories/<owner>/<name>/name")
def rename_repository_application(
    owner: str,
    name: str,
):
    """Set the application name shown for a GitHub-connected application."""

    full_name = f"{owner}/{name}"

    if github_auth.enabled():

        user = github_auth.current_user()

        if user is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Sign in with GitHub to rename an application.",
                }
            ), 401

        repository = user.repositories.get(full_name.lower())

        if repository is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Application not found.",
                }
            ), 404

        if not repository["can_trigger"]:

            return jsonify(
                {
                    "success": False,
                    "error": "Renaming needs write access to the application's GitHub repository.",
                }
            ), 403

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

        return jsonify(
            {
                "success": False,
                "error": problem,
            }
        ), 400

    label = application_names.normalise(value)

    application_names.set_name(full_name, label)

    for summary in list_applications():

        if summary.get("platform") == "Repository" and github_auth.repository_name(summary).lower() == full_name.lower():

            record = load_application(summary["id"])
            record["name"] = label
            save_application(record)

    return jsonify(
        {
            "success": True,
            "name": label,
        }
    )


# ============================================================
# Development server
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=os.environ.get("SECGUARD_DEBUG") == "1",
    )