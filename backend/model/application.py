from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass
class Application:
    """
    Persistent representation of an application being analyzed.

    This object is deliberately platform-neutral. Mendix-specific
    information will be added later through the platform engines.
    """

    id: str
    name: str
    requested_url: str
    final_url: str

    platform: str = "Unknown"

    status_code: int | None = None
    response_time_ms: float | None = None

    created_at: str = ""
    updated_at: str = ""

    status: str = "discovered"

    technologies: list[dict[str, Any]] = field(
        default_factory=list
    )

    attack_surface: dict[str, Any] = field(
        default_factory=dict
    )

    security: dict[str, Any] = field(
        default_factory=lambda: {
            "findings": [],
            "risk_score": 0,
            "recommendations": [],
        }
    )

    model: dict[str, Any] = field(
        default_factory=lambda: {
            "modules": [],
            "entities": [],
            "attributes": [],
            "associations": [],
            "microflows": [],
            "nanoflows": [],
            "pages": [],
            "roles": [],
            "module_roles": [],
            "access_rules": [],
            "apis": [],
        }
    )

    @classmethod
    def create(
        cls,
        requested_url: str,
        final_url: str,
        name: str | None = None,
    ) -> "Application":

        now = datetime.now(
            timezone.utc
        ).isoformat()

        application_name = (
            name
            or final_url
        )

        return cls(
            id=str(uuid4()),
            name=application_name,
            requested_url=requested_url,
            final_url=final_url,
            created_at=now,
            updated_at=now,
        )

    def update_timestamp(self) -> None:

        self.updated_at = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

    def set_platform(
        self,
        platform: str,
    ) -> None:

        self.platform = platform
        self.update_timestamp()

    def to_dict(self) -> dict[str, Any]:

        return asdict(self)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "Application":

        return cls(
            id=data["id"],
            name=data["name"],
            requested_url=data["requested_url"],
            final_url=data["final_url"],
            platform=data.get(
                "platform",
                "Unknown",
            ),
            status_code=data.get(
                "status_code"
            ),
            response_time_ms=data.get(
                "response_time_ms"
            ),
            created_at=data.get(
                "created_at",
                "",
            ),
            updated_at=data.get(
                "updated_at",
                "",
            ),
            status=data.get(
                "status",
                "discovered",
            ),
            technologies=data.get(
                "technologies",
                [],
            ),
            attack_surface=data.get(
                "attack_surface",
                {},
            ),
            security=data.get(
                "security",
                {},
            ),
            model=data.get(
                "model",
                {},
            ),
        )