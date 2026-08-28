from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = (
    "Application-Security-Platform/0.1 "
    "(authorized-security-discovery)"
)


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


def crawl(
    start_url: str,
    max_pages: int = 20,
) -> dict:

    start_url = normalize_url(
        start_url
    )

    queue = deque([start_url])
    visited = set()

    pages = []
    links = []
    forms = []
    scripts = []

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
        }
    )

    while queue and len(visited) < max_pages:

        current = queue.popleft()

        if current in visited:
            continue

        visited.add(current)

        try:

            response = session.get(
                current,
                timeout=15,
                allow_redirects=True,
            )

        except requests.RequestException:
            continue

        page_record = {
            "url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type",
                "",
            ),
        }

        pages.append(
            page_record
        )

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        for anchor in soup.find_all(
            "a",
            href=True,
        ):

            absolute = urljoin(
                response.url,
                anchor["href"],
            )

            if not is_same_origin(
                start_url,
                absolute,
            ):
                continue

            absolute = absolute.split(
                "#",
                1,
            )[0]

            if absolute not in links:
                links.append(
                    absolute
                )

            if (
                absolute not in visited
                and absolute not in queue
                and len(visited) + len(queue)
                < max_pages
            ):

                queue.append(
                    absolute
                )

        for form in soup.find_all(
            "form"
        ):

            action = urljoin(
                response.url,
                form.get(
                    "action",
                    "",
                ),
            )

            method = form.get(
                "method",
                "GET",
            ).upper()

            inputs = []

            for field in form.find_all(
                [
                    "input",
                    "textarea",
                    "select",
                ]
            ):

                inputs.append(
                    {
                        "name":
                            field.get(
                                "name",
                                "",
                            ),

                        "type":
                            field.get(
                                "type",
                                field.name,
                            ),

                        "autocomplete":
                            field.get(
                                "autocomplete",
                                "",
                            ),
                    }
                )

            forms.append(
                {
                    "page":
                        response.url,

                    "action":
                        action,

                    "method":
                        method,

                    "autocomplete":
                        form.get(
                            "autocomplete",
                            "",
                        ),

                    "inputs":
                        inputs,
                }
            )

        for script in soup.find_all(
            "script",
            src=True,
        ):

            script_url = urljoin(
                response.url,
                script["src"],
            )

            if script_url not in scripts:
                scripts.append(
                    script_url
                )

    return {
        "pages": pages,
        "links": links,
        "forms": forms,
        "scripts": scripts,
        "pages_scanned": len(pages),
    }