from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from backend.risk.confidence import FIRM, normalize_confidence
from backend.risk.scoring import finding_score
from backend.risk.severity import normalize_severity

# Finding categories. Kept as plain strings so platform engines can add
# their own without importing this module.
CONFIGURATION = "configuration"
TRANSPORT = "transport"
AUTHENTICATION = "authentication"
AUTHORIZATION = "authorization"
SESSION = "session"
INFORMATION_DISCLOSURE = "information-disclosure"
API = "api"
INPUT_VALIDATION = "input-validation"


@dataclass
class ScanContext:
    """Everything a generic rule may inspect about a target."""

    application_id: str
    requested_url: str
    final_url: str
    platform: str = "Unknown"
    response: dict[str, Any] = field(default_factory=dict)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    attack_surface: dict[str, Any] = field(default_factory=dict)

    @property
    def headers(self) -> dict[str, str]:
        """Response headers, lower-cased keys."""

        return {
            str(key).lower(): str(value)
            for key, value in (self.response.get("headers") or {}).items()
        }

    @property
    def cookies(self) -> list[dict[str, Any]]:
        return [
            cookie
            for cookie in (self.response.get("cookies") or [])
            if isinstance(cookie, dict)
        ]

    @property
    def is_https(self) -> bool:
        return urlparse(self.final_url).scheme == "https"

    @property
    def body(self) -> str:
        return str(self.response.get("body") or "")

    @property
    def forms(self) -> list[dict[str, Any]]:
        return list(self.attack_surface.get("forms") or [])

    @property
    def pages(self) -> list[dict[str, Any]]:
        return list(self.attack_surface.get("pages") or [])

    @property
    def scripts(self) -> list[str]:
        return list(self.attack_surface.get("scripts") or [])

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def has_header(self, name: str) -> bool:
        return name.lower() in self.headers


@dataclass
class Finding:
    """A single normalized security finding."""

    rule_id: str
    title: str
    severity: str
    category: str
    description: str = ""
    recommendation: str = ""
    confidence: str = FIRM
    platform: str = "Generic"
    location: str = ""
    cwe: str = ""
    owasp: str = ""
    references: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    detected_at: str = ""
    risk: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.confidence = normalize_confidence(self.confidence)

        if not self.id:
            self.id = str(uuid4())

        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()

        if not self.risk:
            self.risk = {
                "score": finding_score(self.severity, self.confidence),
                "severity": self.severity,
            }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Rule:
    """
    Base class for every generic rule.

    Subclasses declare their metadata as class attributes and implement
    `evaluate`, returning zero or more findings.
    """

    id: str = ""
    title: str = ""
    severity: str = "medium"
    category: str = CONFIGURATION
    confidence: str = FIRM
    description: str = ""
    recommendation: str = ""
    cwe: str = ""
    owasp: str = ""
    references: tuple[str, ...] = ()
    platform: str = "Generic"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        context: ScanContext,
        *,
        title: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        description: str | None = None,
        recommendation: str | None = None,
        location: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a finding pre-filled from this rule's metadata."""

        return Finding(
            rule_id=self.id,
            title=title or self.title,
            severity=severity or self.severity,
            category=self.category,
            description=description or self.description,
            recommendation=recommendation or self.recommendation,
            confidence=confidence or self.confidence,
            platform=self.platform,
            location=location or context.final_url,
            cwe=self.cwe,
            owasp=self.owasp,
            references=list(self.references),
            evidence=evidence or {},
        )
