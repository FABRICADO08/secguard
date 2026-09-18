"""
A small, hand-checked advisory set for components a scan can see.

The dataset is deliberately narrow: every entry names a public advisory
and the release that fixed it, so a finding can be justified rather than
guessed at. It is not a substitute for a full vulnerability feed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The first dotted numeric run: everything after it (`-rc1`, `+build3`)
# describes the same release, not a further component.
RELEASE = re.compile(r"\d+(?:\.\d+)*")


@dataclass(frozen=True)
class Advisory:
    identifier: str
    severity: str
    summary: str
    fixed_in: str
    introduced_in: str = "0"


@dataclass(frozen=True)
class EndOfLife:
    """A branch that no longer receives security fixes at all."""

    unsupported_below: str
    note: str


def parse_version(value: str) -> tuple[int, ...]:
    """
    Numeric release components, ignoring pre-release and build suffixes.

    `1.10.2-rc1` and `1.10.2` compare equal: a pre-release of a fixed
    version is close enough that reporting it would be noise.
    """

    match = RELEASE.search(value)

    if match is None:
        return (0,)

    return tuple(int(part) for part in match.group(0).split(".")[:4])


def _pad(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))

    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))

    if padded_left < padded_right:
        return -1

    return 0 if padded_left == padded_right else 1


def version_lt(left: str, right: str) -> bool:
    return _pad(parse_version(left), parse_version(right)) < 0


def version_ge(left: str, right: str) -> bool:
    return not version_lt(left, right)


# Component names are normalised (lower case, no punctuation) before
# lookup so "jQuery UI" and "jquery-ui" reach the same entry.
ADVISORIES: dict[str, tuple[Advisory, ...]] = {
    "jquery": (
        Advisory(
            "CVE-2020-11023",
            "medium",
            "Passing HTML containing <option> elements to DOM manipulation "
            "methods executes untrusted code.",
            "3.5.0",
        ),
        Advisory(
            "CVE-2019-11358",
            "medium",
            "jQuery.extend(true, {}, ...) can be tricked into polluting "
            "Object.prototype.",
            "3.4.0",
        ),
        Advisory(
            "CVE-2015-9251",
            "medium",
            "Cross-domain ajax requests execute responses served as text/"
            "javascript even without dataType: script.",
            "3.0.0",
        ),
    ),
    "jquery-ui": (
        Advisory(
            "CVE-2022-31160",
            "medium",
            "The checkboxradio widget renders unsanitised label markup.",
            "1.13.2",
        ),
        Advisory(
            "CVE-2021-41182",
            "medium",
            "The datepicker altField option accepts untrusted markup.",
            "1.13.0",
        ),
    ),
    "bootstrap": (
        Advisory(
            "CVE-2019-8331",
            "medium",
            "data-template attributes on tooltip and popover allow XSS.",
            "3.4.1",
            introduced_in="3.0.0",
        ),
        Advisory(
            "CVE-2019-8331",
            "medium",
            "data-template attributes on tooltip and popover allow XSS.",
            "4.3.1",
            introduced_in="4.0.0",
        ),
    ),
    "angularjs": (
        Advisory(
            "CVE-2022-25869",
            "medium",
            "Interpolation of untrusted content in <textarea> can lead to "
            "content spoofing and XSS.",
            "999.0.0",
        ),
    ),
    "lodash": (
        Advisory(
            "CVE-2021-23337",
            "high",
            "_.template with an attacker-controlled options object allows "
            "command injection.",
            "4.17.21",
        ),
        Advisory(
            "CVE-2020-8203",
            "high",
            "_.zipObjectDeep and friends allow prototype pollution.",
            "4.17.19",
        ),
    ),
    "underscore": (
        Advisory(
            "CVE-2021-23358",
            "high",
            "_.template allows arbitrary code execution through the "
            "variable option.",
            "1.12.1",
        ),
    ),
    "moment": (
        Advisory(
            "CVE-2022-31129",
            "medium",
            "Parsing very long date strings is quadratic and blocks the "
            "event loop.",
            "2.29.4",
        ),
        Advisory(
            "CVE-2022-24785",
            "high",
            "The locale loader accepts path traversal in the locale name.",
            "2.29.2",
        ),
    ),
    "handlebars": (
        Advisory(
            "CVE-2021-23369",
            "high",
            "Templates compiled with compat mode allow remote code "
            "execution through prototype access.",
            "4.7.7",
        ),
    ),
    "axios": (
        Advisory(
            "CVE-2023-45857",
            "medium",
            "The XSRF token is sent to third-party hosts on cross-origin "
            "requests.",
            "1.6.0",
        ),
        Advisory(
            "CVE-2020-28168",
            "medium",
            "Proxy settings are ignored on redirect, allowing SSRF.",
            "0.21.1",
        ),
    ),
    "dompurify": (
        Advisory(
            "CVE-2020-26870",
            "medium",
            "Sanitisation can be bypassed through mutation XSS in nested "
            "elements.",
            "2.0.17",
        ),
    ),
    "ckeditor": (
        Advisory(
            "CVE-2021-33829",
            "medium",
            "The HTML data processor allows XSS through crafted pasted "
            "content.",
            "4.16.2",
            introduced_in="4.0.0",
        ),
    ),
    "nginx": (
        Advisory(
            "CVE-2021-23017",
            "high",
            "An off-by-one in the DNS resolver allows memory corruption "
            "when the resolver directive is used.",
            "1.20.1",
        ),
    ),
    "apache": (
        Advisory(
            "CVE-2023-25690",
            "high",
            "Request smuggling through mod_proxy rewrite rules with "
            "unsafe variable substitution.",
            "2.4.56",
            introduced_in="2.4.0",
        ),
    ),
    "php": (
        Advisory(
            "CVE-2022-31626",
            "high",
            "A buffer overflow in the mysqlnd password handling allows "
            "remote code execution.",
            "7.4.30",
            introduced_in="7.0.0",
        ),
        Advisory(
            "CVE-2022-31626",
            "high",
            "A buffer overflow in the mysqlnd password handling allows "
            "remote code execution.",
            "8.0.20",
            introduced_in="8.0.0",
        ),
    ),
}

# Branches that receive no security fixes at all. Reported separately
# from a specific advisory: the risk is the absence of future patches.
END_OF_LIFE: dict[str, EndOfLife] = {
    "angularjs": EndOfLife(
        "999.0.0",
        "AngularJS reached end of life in January 2022 and receives no "
        "security fixes.",
    ),
    "jquery": EndOfLife(
        "3.0.0",
        "jQuery 1.x and 2.x are no longer maintained.",
    ),
    "bootstrap": EndOfLife(
        "4.0.0",
        "Bootstrap 3 is no longer maintained.",
    ),
    "php": EndOfLife(
        "8.1.0",
        "PHP branches below 8.1 no longer receive security support.",
    ),
    "moment": EndOfLife(
        "0",
        "Moment.js is in maintenance mode and its authors recommend "
        "migrating to a modern date library.",
    ),
}


def normalize_name(name: str) -> str:
    lowered = name.strip().lower()

    lowered = lowered.replace(" ", "-").replace("_", "-").replace(".js", "")

    return {
        "angular": "angularjs",
        "apache-httpd": "apache",
        "httpd": "apache",
        "jqueryui": "jquery-ui",
    }.get(lowered, lowered)


def advisories_for(name: str, version: str) -> list[Advisory]:
    """Advisories whose affected range contains this version."""

    if not version:
        return []

    return [
        advisory
        for advisory in ADVISORIES.get(normalize_name(name), ())
        if version_ge(version, advisory.introduced_in)
        and version_lt(version, advisory.fixed_in)
    ]


def end_of_life_for(name: str, version: str) -> EndOfLife | None:
    entry = END_OF_LIFE.get(normalize_name(name))

    if entry is None or not version:
        return None

    if entry.unsupported_below == "0":
        return entry

    return entry if version_lt(version, entry.unsupported_below) else None
