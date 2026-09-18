from __future__ import annotations

import html
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from backend.config.settings import PROBE_TIMEOUT
from backend.discovery.crawler import is_same_origin
from backend.discovery.http import build_session

# Only a handful of parameters are probed: each one costs a request, and
# the point is to show that unescaped reflection exists, not to enumerate
# every instance of it.
MAX_PROBES = 8

# Deliberately inert. The marker carries the characters that matter for
# HTML context (quote, angle brackets) but forms no tag or attribute, so
# nothing is injected into the target beyond a harmless string.
MARKER_CHARS = "\"'<>"

# Field types whose value is not user-controlled text.
SKIPPED_INPUT_TYPES = {
    "submit",
    "button",
    "reset",
    "image",
    "file",
    "hidden",
}


def _marker() -> str:
    return f"sgp{secrets.token_hex(4)}"


def _with_params(url: str, params: dict[str, str]) -> str:
    parts = urlparse(url)

    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)

    return urlunparse(parts._replace(query=urlencode(query)))


def probe_targets(
    forms: list[dict[str, Any]],
    links: list[str],
    base_url: str,
) -> list[dict[str, str]]:
    """
    Pick GET parameters worth probing.

    Only GET is probed: replaying a POST could create or change data on a
    target the scan is only authorized to read.
    """

    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, parameter: str, source: str) -> None:
        if not parameter or not is_same_origin(base_url, url):
            return

        key = (url.split("?", 1)[0], parameter)

        if key in seen:
            return

        seen.add(key)

        targets.append(
            {
                "url": url,
                "parameter": parameter,
                "source": source,
            }
        )

    for form in forms:
        if str(form.get("method", "GET")).upper() != "GET":
            continue

        action = str(form.get("action") or form.get("page") or "")

        for field in form.get("inputs") or []:
            if str(field.get("type", "")).lower() in SKIPPED_INPUT_TYPES:
                continue

            add(action, str(field.get("name") or ""), "form")

    for link in links:
        for name, _value in parse_qsl(urlparse(link).query):
            add(link, name, "link")

    return targets


def reflection_context(body: str, payload: str, marker: str) -> str:
    """
    Describe how the marker came back.

    "raw" means the quotes and angle brackets survived, "escaped" means
    they were entity-encoded, and "encoded" means the marker is present in
    some other transformed form (percent-encoding, stripped characters).
    """

    if payload in body:
        return "raw"

    if html.escape(payload, quote=True) in body:
        return "escaped"

    if marker in body:
        return "encoded"

    return "none"


def probe_reflection(
    forms: list[dict[str, Any]],
    links: list[str],
    base_url: str,
    max_probes: int = MAX_PROBES,
) -> dict[str, Any]:
    """
    Send an inert marker through GET parameters and see how it comes back.

    A parameter that echoes the marker with its quotes and angle brackets
    intact is rendering attacker-controlled text into the page unescaped,
    which is the precondition for reflected cross-site scripting.
    """

    session = build_session()

    probes: list[dict[str, Any]] = []
    reflected: list[dict[str, Any]] = []

    for target in probe_targets(forms, links, base_url)[:max_probes]:
        marker = _marker()
        payload = f"{MARKER_CHARS}{marker}"

        url = _with_params(target["url"], {target["parameter"]: payload})

        try:
            response = session.get(
                url,
                timeout=PROBE_TIMEOUT,
                allow_redirects=True,
            )

        except requests.RequestException:
            continue

        body = response.text or ""

        context = reflection_context(body, payload, marker)

        record = {
            "url": target["url"],
            "parameter": target["parameter"],
            "source": target["source"],
            "status_code": response.status_code,
            "reflected": context != "none",
            "context": context,
        }

        probes.append(record)

        if record["reflected"]:
            reflected.append(record)

    return {
        "probes": probes,
        "reflected": reflected,
        "probe_count": len(probes),
    }
