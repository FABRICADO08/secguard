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

        score = min(
            base_score + self._risk_points(
                sensitive=sensitive,
                sensitivity_severity=sensitivity_severity,
                create=create,
                delete=delete,
                write=write,
                xpath=xpath,
                broad_roles=broad_roles,
                bypasses_entity_access=bypasses_entity_access,
            ),
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
    def _risk_points(
        *,
        sensitive: bool,
        sensitivity_severity: str,
        create: bool,
        delete: bool,
        write: bool,
        xpath: bool,
        broad_roles: bool,
        bypasses_entity_access: bool,
    ) -> int:
        score = (
            15 * bool(write)
            + 10 * bool(create)
            + 20 * bool(delete)
            + 20 * bool(sensitive)
            + 15 * bool(broad_roles)
            + 25 * bool(bypasses_entity_access)
        )

        if sensitivity_severity == "high":
            score += 10
        elif sensitivity_severity == "critical":
            score += 20

        if not xpath and (create or delete or write):
            score += 15

        return score

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