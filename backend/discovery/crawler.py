from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from backend.discovery.http import build_session


def normalize_url(url: str) -> str:
    return url.rstrip("/")


def is_same_origin(
    base_url: str,
    candidate_url: str,
) -> bool:

    base = urlparse(base_url)
    candidate = urlparse(candidate_url)

    return (
        candidate.scheme in {
            "http",
            "https",
        }
        and candidate.netloc == base.netloc
    )


def _record_links(
    soup: BeautifulSoup,
    page_url: str,
    start_url: str,
    state: dict,
    max_pages: int,
) -> None:
    for anchor in soup.find_all("a", href=True):
        absolute = urljoin(page_url, anchor["href"])

        if not is_same_origin(start_url, absolute):
            continue

        absolute = absolute.split("#", 1)[0]

        if absolute not in state["links"]:
            state["links"].append(absolute)

        if (
            absolute not in state["visited"]
            and absolute not in state["queue"]
            and len(state["visited"]) + len(state["queue"]) < max_pages
        ):
            state["queue"].append(absolute)


def _record_forms(soup: BeautifulSoup, page_url: str, forms: list[dict]) -> None:
    for form in soup.find_all("form"):
        inputs = [
            {
                "name": field.get("name", ""),
                "type": field.get("type", field.name),
                "autocomplete": field.get("autocomplete", ""),
            }
            for field in form.find_all(["input", "textarea", "select"])
        ]
        forms.append(
            {
                "page": page_url,
                "action": urljoin(page_url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "autocomplete": form.get("autocomplete", ""),
                "inputs": inputs,
            }
        )


def _record_scripts(soup: BeautifulSoup, page_url: str, scripts: list[str]) -> None:
    for script in soup.find_all("script", src=True):
        script_url = urljoin(page_url, script["src"])

        if script_url not in scripts:
            scripts.append(script_url)


def _process_page(
    response,
    start_url: str,
    state: dict,
    max_pages: int,
) -> None:
    state["pages"].append(
        {
            "url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
        }
    )
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return

    soup = BeautifulSoup(response.text, "html.parser")
    _record_links(
        soup,
        response.url,
        start_url,
        state,
        max_pages,
    )
    _record_forms(soup, response.url, state["forms"])
    _record_scripts(soup, response.url, state["scripts"])


def crawl(
    start_url: str,
    max_pages: int = 20,
) -> dict:
    start_url = normalize_url(
        start_url
    )

    state = {
        "queue": deque([start_url]),
        "visited": set(),
        "pages": [],
        "links": [],
        "forms": [],
        "scripts": [],
    }

    # Shared session so crawled pages are subject to the same target
    # policy: a page may otherwise redirect the crawler internally.
    session = build_session()

    while state["queue"] and len(state["visited"]) < max_pages:

        current = state["queue"].popleft()

        if current in state["visited"]:
            continue

        state["visited"].add(current)

        try:

            response = session.get(
                current,
                timeout=15,
                allow_redirects=True,
            )

        except requests.RequestException:
            continue

        _process_page(response, start_url, state, max_pages)

    return {
        "pages": state["pages"],
        "links": state["links"],
        "forms": state["forms"],
        "scripts": state["scripts"],
        "pages_scanned": len(state["pages"]),
    }