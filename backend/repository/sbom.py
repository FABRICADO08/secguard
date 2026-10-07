"""Software Bill of Materials export in CycloneDX 1.5 and SPDX 2.3 JSON."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from backend.repository.manifests import normalize_package
from backend.repository.versions import GO, MAVEN, NPM, PACKAGIST, PYPI, RUBYGEMS

TOOL_NAME = "SecGuard"
TOOL_VERSION = "1.0"

_PURL_TYPES = {PYPI: "pypi", NPM: "npm", GO: "golang", MAVEN: "maven", PACKAGIST: "composer", RUBYGEMS: "gem"}


def purl(ecosystem: str, name: str, version: str) -> str:
    kind = _PURL_TYPES.get(ecosystem)

    if kind is None:
        return ""

    if ecosystem == MAVEN and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group)}/{quote(artifact)}"
    elif ecosystem == NPM and name.startswith("@"):
        scope, package = name.split("/", 1)
        path = f"%40{quote(scope[1:])}/{quote(package)}"
    else:
        path = "/".join(quote(part) for part in normalize_package(ecosystem, name).split("/"))

    return f"pkg:{kind}/{path}" + (f"@{quote(version)}" if version else "")


def _license_choice(license_text: str, spdx_id: bool) -> list[dict[str, Any]]:
    if not license_text:
        return []

    if spdx_id and re.fullmatch(r"[A-Za-z0-9.+-]+", license_text):
        return [{"license": {"id": license_text}}]

    if re.search(r"\s(OR|AND|WITH)\s", license_text):
        return [{"expression": license_text}]

    return [{"license": {"name": license_text}}]


def cyclonedx(report: dict[str, Any]) -> dict[str, Any]:
    repository = report.get("repository") or {}

    components = []

    for dependency in report.get("dependencies") or []:
        reference = dependency.get("purl") or f"{dependency['ecosystem']}:{dependency['name']}@{dependency.get('version', '')}"

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": reference,
            "name": dependency["name"],
            "scope": "optional" if dependency.get("scope") == "development" else "required",
        }

        if dependency.get("version"):
            component["version"] = dependency["version"]

        if dependency.get("purl"):
            component["purl"] = dependency["purl"]

        licenses = _license_choice(dependency.get("license_spdx") or "", True) or _license_choice(dependency.get("license") or "", False)

        if licenses:
            component["licenses"] = licenses

        components.append(component)

    vulnerabilities = [
        {
            "bom-ref": f"{item['id']}:{item['package']}@{item['version']}",
            "id": item["id"],
            "source": {"name": "OSV", "url": item.get("url", "")},
            "ratings": [{"severity": item.get("severity", "unknown"), **({"score": item["cvss"], "method": "CVSSv3"} if item.get("cvss") is not None else {})}],
            "description": item.get("summary", ""),
            "recommendation": f"Upgrade to {item['minimum_fix']}" if item.get("minimum_fix") else "",
            "affects": [{"ref": item.get("purl") or ""}],
        }
        for item in report.get("vulnerabilities") or []
    ]

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.get("generated_at") or datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": repository.get("name") or "repository",
                **({"version": repository["commit"]} if repository.get("commit") else {}),
            },
        },
        "components": components,
        "dependencies": [
            {"ref": "root", "dependsOn": [component["bom-ref"] for component in components]}
        ],
    }

    if vulnerabilities:
        document["vulnerabilities"] = vulnerabilities

    return document


def _spdx_id(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")


def spdx(report: dict[str, Any]) -> dict[str, Any]:
    repository = report.get("repository") or {}
    name = repository.get("name") or "repository"

    root_id = "SPDXRef-Root"

    packages = [
        {
            "SPDXID": root_id,
            "name": name,
            "versionInfo": repository.get("commit") or "",
            "downloadLocation": repository.get("url") or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": repository.get("license") or "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    ]

    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]

    seen: set[str] = set()

    for dependency in report.get("dependencies") or []:
        identifier = _spdx_id(f"{dependency['ecosystem']}-{dependency['name']}-{dependency.get('version') or 'unresolved'}")

        if identifier in seen:
            continue

        seen.add(identifier)

        package: dict[str, Any] = {
            "SPDXID": identifier,
            "name": dependency["name"],
            "versionInfo": dependency.get("version") or "",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": dependency.get("license_spdx") or "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }

        if dependency.get("purl"):
            package["externalRefs"] = [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": dependency["purl"]}
            ]

        packages.append(package)

        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEV_DEPENDENCY_OF" if dependency.get("scope") == "development" else "DEPENDS_ON",
                "relatedSpdxElement": identifier,
            }
        )

    # DEV_DEPENDENCY_OF reads "A is a dev dependency of B", so swap ends.
    for relationship in relationships:
        if relationship["relationshipType"] == "DEV_DEPENDENCY_OF":
            relationship["spdxElementId"], relationship["relatedSpdxElement"] = (
                relationship["relatedSpdxElement"],
                relationship["spdxElementId"],
            )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name} SBOM",
        "documentNamespace": f"https://secguard.local/spdx/{quote(name)}/{uuid4()}",
        "creationInfo": {
            "created": (report.get("generated_at") or datetime.now(timezone.utc).isoformat()).split(".")[0].replace("+00:00", "") + "Z",
            "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
