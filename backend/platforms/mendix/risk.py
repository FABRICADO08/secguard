from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class RiskInputs:
    base_score: int = 0
    sensitive: bool = False
    sensitivity_severity: str = "low"
    create: bool = False
    delete: bool = False
    write: bool = False
    xpath: bool = False
    broad_roles: bool = False
    bypasses_entity_access: bool = False


class RiskEngine:

    SEVERITY_ORDER = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def calculate(self, inputs: RiskInputs) -> Dict:
        score = min(self._score(inputs), 100)

        return {
            "score":
                score,

            "severity":
                self.severity_from_score(
                    score
                ),
        }

    def _score(self, inputs: RiskInputs) -> int:
        return (
            inputs.base_score
            + self._access_score(inputs)
            + self._sensitivity_score(inputs)
            + (15 if inputs.broad_roles else 0)
            + self._unrestricted_write_score(inputs)
            + (25 if inputs.bypasses_entity_access else 0)
        )

    @staticmethod
    def _access_score(inputs: RiskInputs) -> int:
        return (
            (15 if inputs.write else 0)
            + (10 if inputs.create else 0)
            + (20 if inputs.delete else 0)
        )

    @staticmethod
    def _sensitivity_score(inputs: RiskInputs) -> int:
        score = 20 if inputs.sensitive else 0
        if inputs.sensitivity_severity == "high":
            score += 10
        elif inputs.sensitivity_severity == "critical":
            score += 20
        return score

    @staticmethod
    def _unrestricted_write_score(inputs: RiskInputs) -> int:
        return 15 if not inputs.xpath and (
            inputs.create or inputs.delete or inputs.write
        ) else 0

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
