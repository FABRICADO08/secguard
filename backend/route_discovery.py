from flask import current_app, jsonify, request

from backend.discovery.fingerprint import (
    CertificateRejectedError,
    TargetUnreachableError,
    validate_url,
)
from backend.discovery.libraries import detect_libraries
from backend.discovery.reflection import probe_reflection
from backend.discovery.robots import discover_robots_and_sitemaps
from backend.discovery.scripts import analyze_scripts
from backend.discovery.tls import analyze_tls
from backend.model.application import Application
from backend.recommendations import build_recommendations
from backend.risk.scoring import summarize
from backend.rules.base import ScanContext
from backend.rules.engine import analyze
from backend.security.auth import require_api_token
from backend.security.rate_limit import rate_limited
from backend.security.targets import BlockedTargetError, assert_target_allowed
from backend.storage.findings import save_findings
from backend.storage.scans import save_application


BLOCKED_TARGET_MESSAGE = (
    "The target, or a page it redirects to, is not allowed: only public "
    "http(s) addresses can be scanned. Set SECGUARD_ALLOW_PRIVATE_TARGETS=1 "
    "or add the host to SECGUARD_ALLOWED_TARGET_HOSTS to scan it deliberately."
)
CERTIFICATE_REJECTED_MESSAGE = "The server's TLS certificate failed validation."


def _blocked_target_response():
    return jsonify(
        {
            "success": False,
            "error": BLOCKED_TARGET_MESSAGE,
            "reason": "blocked_target",
        }
    ), 403


def _analyze_and_save(application, response, technologies, status, observed=True):
    analysis = analyze(
        ScanContext(
            application_id=application.id,
            requested_url=application.requested_url,
            final_url=application.final_url,
            platform=application.platform,
            response=response,
            technologies=technologies,
            attack_surface=application.attack_surface,
            response_observed=observed,
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
    application.status = status
    application.update_timestamp()
    save_application(application.to_dict())
    save_findings(application.id, findings)


def _certificate_response(requested_url, final_url):
    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": None,
        "https": True,
        "headers": {},
        "cookies": [],
        "body": "",
        "redirect_chain": [],
        "http_redirect": {"tested": False},
    }


def _certificate_attack_surface(tls_result):
    return {
        "pages": [],
        "links": [],
        "forms": [],
        "scripts": [],
        "endpoints": [],
        "potential_api_paths": [],
        "exposed_paths": [],
        "pages_scanned": 0,
        "tls": tls_result,
    }


def _certificate_only_scan(url: str, error: str, rejected_url: str = ""):
    requested_url = validate_url(url)
    final_url = validate_url(rejected_url) if rejected_url else requested_url
    assert_target_allowed(final_url)
    tls_result = analyze_tls(final_url)
    response = _certificate_response(requested_url, final_url)
    application = Application.create(
        requested_url=requested_url, final_url=final_url
    )
    application.set_platform("Generic")
    application.attack_surface = _certificate_attack_surface(tls_result)
    _analyze_and_save(
        application, response, [], "certificate_rejected", observed=False
    )
    return jsonify(
        {
            "success": True,
            "partial": True,
            "reason": "certificate_rejected",
            "error": error,
            "application_id": application.id,
            "application": application.to_dict(),
        }
    )


def _discover_surface(compatibility, response):
    technologies = compatibility.detect_technologies(response)
    crawl_result = compatibility.crawl(response["final_url"], max_pages=20)
    endpoints = compatibility.discover_endpoints(
        crawl_result["links"], crawl_result["forms"]
    )
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
    potential_api_paths = compatibility.discover_common_api_paths(
        response["final_url"]
    )
    exposed_paths = compatibility.scan_exposed_paths(response["final_url"])
    tls_result = analyze_tls(response["final_url"])
    return {
        "technologies": technologies,
        "crawl": crawl_result,
        "endpoints": endpoints,
        "robots": robots_result,
        "scripts": script_result,
        "libraries": libraries,
        "reflection": reflection_result,
        "potential_api_paths": potential_api_paths,
        "exposed_paths": exposed_paths,
        "tls": tls_result,
    }


def _attack_surface(discovered):
    crawl = discovered["crawl"]
    return {
        "pages": crawl["pages"],
        "links": crawl["links"],
        "forms": crawl["forms"],
        "scripts": crawl["scripts"],
        "endpoints": discovered["endpoints"],
        "script_endpoints": discovered["scripts"]["endpoints"],
        "script_analysis": {"scripts": discovered["scripts"]["scripts"]},
        "libraries": discovered["libraries"],
        "robots": discovered["robots"]["robots"],
        "sitemap": discovered["robots"]["sitemap"],
        "reflection": discovered["reflection"],
        "potential_api_paths": discovered["potential_api_paths"],
        "exposed_paths": discovered["exposed_paths"],
        "pages_scanned": crawl["pages_scanned"],
        "tls": discovered["tls"],
    }


def _create_application(response, discovered):
    technologies = discovered["technologies"]
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
    application.attack_surface = _attack_surface(discovered)
    return application


def _discover_application(url, compatibility):
    try:
        assert_target_allowed(url)
        response = compatibility.fetch_application(url)
        discovered = _discover_surface(compatibility, response)
        application = _create_application(response, discovered)
        _analyze_and_save(
            application, response, discovered["technologies"], "analyzed"
        )
        return jsonify(
            {
                "success": True,
                "application_id": application.id,
                "application": application.to_dict(),
            }
        )
    except BlockedTargetError:
        return _blocked_target_response()
    except ValueError:
        return jsonify(
            {
                "success": False,
                "error": "Enter a valid http:// or https:// application URL.",
            }
        ), 400
    except CertificateRejectedError as exc:
        try:
            return _certificate_only_scan(
                url, CERTIFICATE_REJECTED_MESSAGE, exc.url
            )
        except BlockedTargetError:
            return _blocked_target_response()
    except TargetUnreachableError:
        return jsonify(
            {
                "success": False,
                "error": f"Could not connect to {url}.",
                "reason": "unreachable",
            }
        ), 502
    except Exception:
        current_app.logger.exception("Application discovery failed.")
        return jsonify(
            {"success": False, "error": "Application discovery failed."}
        ), 500


def register_routes(app, compatibility):
    @app.post("/api/discover")
    @require_api_token
    @rate_limited
    def discover():
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "") or "").strip()
        if not url:
            return jsonify(
                {"success": False, "error": "Application URL is required."}
            ), 400
        return _discover_application(url, compatibility)
