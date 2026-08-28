from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from backend.risk.severity import severity_rank
from backend.rules.base import Finding, Rule, ScanContext
from backend.rules.generic import all_generic_rules


class RuleEngine:
    """Runs a set of rules against a scan context and returns findings."""

    def __init__(self, rules: Sequence[Rule] | None = None) -> None:
        self.rules: list[Rule] = list(rules or [])
        self.errors: list[dict[str, str]] = []

    def register(self, rule: Rule) -> None:
        self.rules.append(rule)

    def register_all(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            self.register(rule)

    def run(self, context: ScanContext) -> list[dict[str, Any]]:
        """
        Evaluate every rule.

        A rule that raises is recorded in `errors` and skipped, so one
        broken rule can never abort a scan.
        """

        self.errors = []

        findings: list[Finding] = []

        for rule in self.rules:
            try:
                findings.extend(rule.evaluate(context) or [])

            except Exception as exc:
                self.errors.append(
                    {
                        "rule_id": rule.id,
                        "error": str(exc),
                    }
                )

        findings.sort(
            key=lambda finding: (
                -severity_rank(finding.severity),
                finding.rule_id,
            )
        )

        return [finding.to_dict() for finding in findings]


def default_rules() -> list[Rule]:
    """Every generic rule shipped with the platform."""

    return all_generic_rules()


def default_engine() -> RuleEngine:
    return RuleEngine(default_rules())


def analyze(context: ScanContext) -> dict[str, Any]:
    """Run the default engine and return findings plus rule errors."""

    engine = default_engine()

    findings = engine.run(context)

    return {
        "findings": findings,
        "rules_evaluated": len(engine.rules),
        "rule_errors": engine.errors,
    }
