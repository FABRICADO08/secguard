from __future__ import annotations

from typing import Dict


class RiskEngine:

    SEVERITY_ORDER = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def calculate(
        self,
        *,
        base_score: int = 0,
        sensitive: bool = False,
        sensitivity_severity: str = "low",
        create: bool = False,
        delete: bool = False,
        write: bool = False,
        xpath: bool = False,
        broad_roles: bool = False,
        bypasses_entity_access: bool = False,
    ) -> Dict:

        score = base_score

        if write:
            score += 15

        if create:
            score += 10

        if delete:
            score += 20

        if sensitive:
            score += 20

        if sensitivity_severity == "high":
            score += 10

        elif sensitivity_severity == "critical":
            score += 20

        if broad_roles:
            score += 15

        if not xpath and (
            create
            or delete
            or write
        ):
            score += 15

        if bypasses_entity_access:
            score += 25

        score = min(
            score,
            100,
        )

        return {
            "score":
                score,

            "severity":
                self.severity_from_score(
                    score
                ),
        }

    @staticmethod
    def severity_from_score(
        score: int,
    ) -> str:

        if score >= 85:
            return "critical"

        if score >= 65:
            return "high"

        if score >= 40:
            return "medium"

        if score >= 20:
            return "low"

        return "informational"