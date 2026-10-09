"""
Open-source licence classification and compliance policy.

Licences are normalised to SPDX identifiers and placed in a category by
how much they constrain a proprietary product that ships them. An SPDX
expression is evaluated the way a distributor may: under ``OR`` the
least restrictive option can be chosen, under ``AND`` every term binds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
NETWORK_COPYLEFT = "network-copyleft"
NON_COMMERCIAL = "non-commercial"
PUBLIC_DOMAIN = "public-domain"
UNKNOWN = "unknown"

# Higher restricts more.
RESTRICTIVENESS = {
    PUBLIC_DOMAIN: 0,
    PERMISSIVE: 1,
    WEAK_COPYLEFT: 2,
    UNKNOWN: 3,
    STRONG_COPYLEFT: 4,
    NETWORK_COPYLEFT: 5,
    NON_COMMERCIAL: 6,
}

CATEGORIES: dict[str, str] = {}

CANONICAL: dict[str, str] = {}

for _category, _identifiers in {
    PUBLIC_DOMAIN: ["CC0-1.0", "Unlicense", "0BSD", "WTFPL"],
    PERMISSIVE: [
        "MIT", "MIT-0", "ISC", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
        "Apache-2.0", "Zlib", "PSF-2.0", "Python-2.0", "BSL-1.0", "X11", "Artistic-2.0",
        "BlueOak-1.0.0", "CC-BY-3.0", "CC-BY-4.0", "PostgreSQL", "HPND", "NCSA", "UPL-1.0",
        "Unicode-DFS-2016", "Unicode-3.0", "OpenSSL", "AFL-3.0",
    ],
    WEAK_COPYLEFT: [
        "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0",
        "CDDL-1.0", "CDDL-1.1", "EUPL-1.1", "EUPL-1.2", "CC-BY-SA-4.0", "OSL-3.0",
    ],
    STRONG_COPYLEFT: [
        "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    ],
    NETWORK_COPYLEFT: ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "OSL-3.0-network"],
    NON_COMMERCIAL: [
        "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0", "BUSL-1.1", "Elastic-2.0",
        "Commons-Clause", "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0",
    ],
}.items():
    for _identifier in _identifiers:
        CATEGORIES[_identifier.lower()] = _category
        CANONICAL[_identifier.lower()] = _identifier

# Free-text licence names registries commonly carry instead of SPDX ids.
ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit/x11": "MIT",
    "expat": "MIT",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "gpl": "GPL-2.0-or-later",
    "gplv2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "lgpl": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu library or lesser general public license (lgpl)": "LGPL-2.1-or-later",
    "agpl-3.0": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "public domain": "Unlicense",
    "unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "zlib/libpng": "Zlib",
    "boost software license 1.0 (bsl-1.0)": "BSL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
}

COMMERCIAL_TERMS = re.compile(r"commercial|proprietary|^unlicensed$", re.IGNORECASE)


def normalize(value: str) -> str:
    text = re.sub(r"\s+", " ", (value or "").strip().strip("()"))

    if not text:
        return ""

    return ALIASES.get(text.lower()) or CANONICAL.get(text.lower()) or text


def category_of(identifier: str) -> str:
    identifier = normalize(identifier)

    if not identifier:
        return UNKNOWN

    if COMMERCIAL_TERMS.search(identifier):
        return NON_COMMERCIAL

    lowered = identifier.lower()

    if lowered in CATEGORIES:
        return CATEGORIES[lowered]

    # Deprecated SPDX ids ("GPL-3.0", "LGPL-2.1+") and close variants.
    for prefix, category in (
        ("agpl", NETWORK_COPYLEFT),
        ("sspl", NETWORK_COPYLEFT),
        ("lgpl", WEAK_COPYLEFT),
        ("gpl", STRONG_COPYLEFT),
        ("mpl", WEAK_COPYLEFT),
        ("epl", WEAK_COPYLEFT),
        ("bsd", PERMISSIVE),
        ("apache", PERMISSIVE),
        ("cc-by-nc", NON_COMMERCIAL),
    ):
        if lowered.startswith(prefix):
            return category

    return UNKNOWN


@dataclass
class LicenseVerdict:
    expression: str
    category: str
    options: list[str]
    dual_license_trap: bool = False


def _split(expression: str, operator: str) -> list[str]:
    parts, depth, current = [], 0, ""
    tokens = re.split(r"(\(|\)|\s+)", expression)

    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1

        if depth == 0 and token.strip().upper() == operator:
            parts.append(current.strip())
            current = ""
        else:
            current += token

    parts.append(current.strip())

    return [part for part in parts if part]


def _strip_outer_parentheses(text: str) -> str:
    text = text.strip()

    while text.startswith("(") and text.endswith(")"):
        depth = 0

        for index, character in enumerate(text):
            depth += character == "("
            depth -= character == ")"

            if depth == 0 and index < len(text) - 1:
                return text

        text = text[1:-1].strip()

    return text


def evaluate(expression: str) -> LicenseVerdict:
    expression = (expression or "").strip()

    if not expression:
        return LicenseVerdict("", UNKNOWN, [])

    text = _strip_outer_parentheses(expression)
    if " " not in text and "/" in text:
        text = text.replace("/", " OR ")

    alternatives = _split(text, "OR")
    if len(alternatives) > 1:
        return _evaluate_alternatives(expression, alternatives)

    conjunction = _split(text, "AND")
    if len(conjunction) > 1:
        return _evaluate_conjunction(expression, conjunction)

    return _evaluate_single(expression, text)


def _evaluate_alternatives(
    expression: str,
    alternatives: list[str],
) -> LicenseVerdict:
    verdicts = [evaluate(option) for option in alternatives]
    best = min(verdicts, key=lambda verdict: RESTRICTIVENESS[verdict.category])
    categories = {verdict.category for verdict in verdicts}
    # "GPL-3.0 OR Commercial": the only free option is copyleft.
    trap = NON_COMMERCIAL in categories and best.category in (
        STRONG_COPYLEFT,
        NETWORK_COPYLEFT,
    )
    return LicenseVerdict(
        expression,
        best.category,
        [normalize(option) for option in alternatives],
        trap,
    )


def _evaluate_conjunction(
    expression: str,
    conjunction: list[str],
) -> LicenseVerdict:
    verdicts = [evaluate(part) for part in conjunction]
    worst = max(verdicts, key=lambda verdict: RESTRICTIVENESS[verdict.category])
    return LicenseVerdict(
        expression,
        worst.category,
        [normalize(part) for part in conjunction],
    )


def _evaluate_single(expression: str, text: str) -> LicenseVerdict:
    base = re.split(r"\s+WITH\s+", text.strip("() "), flags=re.IGNORECASE)
    category = category_of(base[0])
    # GPL with a linking exception (Classpath, GCC runtime) behaves like
    # a weak copyleft for code that only links against it.
    if len(base) > 1 and category == STRONG_COPYLEFT:
        category = WEAK_COPYLEFT
    return LicenseVerdict(expression, category, [normalize(base[0])])


def project_license(texts: dict[str, str]) -> str:
    """Best-effort SPDX id of the scanned project from its own files."""

    declared = texts.get("declared", "").strip()

    if declared:
        return normalize(declared)

    body = texts.get("LICENSE", "")[:4000].lower()

    for needle, identifier in (
        ("gnu affero general public license", "AGPL-3.0-only"),
        ("gnu lesser general public license", "LGPL-3.0-only"),
        ("gnu general public license", "GPL-3.0-only"),
        ("mozilla public license", "MPL-2.0"),
        ("apache license", "Apache-2.0"),
        ("permission is hereby granted, free of charge", "MIT"),
        ("redistribution and use in source and binary forms", "BSD-3-Clause"),
        ("this is free and unencumbered software", "Unlicense"),
    ):
        if needle in body:
            return identifier

    return ""


def conflicts_with_project(dependency_category: str, project_category: str) -> bool:
    """
    Whether a dependency's licence imposes obligations the project's own
    licence does not already accept. A GPL project may use GPL code; a
    proprietary or permissive one inherits the copyleft.
    """

    if dependency_category in (PUBLIC_DOMAIN, PERMISSIVE):
        return False

    if dependency_category == NON_COMMERCIAL:
        return True

    if project_category == NETWORK_COPYLEFT:
        return False

    if project_category == STRONG_COPYLEFT:
        return dependency_category == NETWORK_COPYLEFT

    return True
