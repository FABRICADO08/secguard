from __future__ import annotations

from typing import Any, Dict, List

class FindingHelpersMixin:
    @classmethod
    def classify_module(
        cls,
        module: str,
    ) -> str:

        if not module:

            return "unknown"

        if module in cls.TECHNICAL_MODULES:

            return "technical"

        return "application"

    def _entity_finding(self, entity, rule, sensitivity, risk, module_type) -> Dict[str, Any]:
        sensitive = sensitivity["sensitive"]
        return {
            "rule_id": "MXSEC-101",
            "category": "Access Control",
            "severity": risk["severity"],
            "score": risk["score"],
            "confidence": self._confidence(module_type, sensitive, rule),
            "title": self._entity_finding_title(rule, sensitive),
            "module": entity.module,
            "module_type": module_type,
            "entity": entity.qualified_name or entity.name,
            "description": (
                "The entity has a combination of access-control conditions "
                "that may permit excessive data access or modification."
            ),
            "roles": list(rule.roles),
            "sensitivity": sensitivity,
            "evidence": self._entity_access_evidence(rule),
            "recommendation": self._recommendation(rule, sensitivity),
        }

    @staticmethod
    def _entity_finding_title(rule, sensitive: bool) -> str:
        if sensitive and rule.allow_delete:
            return "Sensitive entity allows deletion"
        if sensitive and rule.has_write_access and rule.allow_create and not rule.has_xpath_constraint:
            return "Sensitive entity has broad write access without row-level restriction"
        if rule.allow_delete and rule.has_write_access and not rule.has_xpath_constraint:
            return "Entity has broad delete/write access without row-level restriction"
        if rule.allow_create and rule.has_write_access and not rule.has_xpath_constraint:
            return "Entity has broad write access without row-level restriction"
        return "Potential excessive entity access"

    @staticmethod
    def _entity_access_evidence(rule) -> Dict[str, Any]:
        return {
            "allow_create": rule.allow_create,
            "allow_delete": rule.allow_delete,
            "member_access": rule.default_member_access_rights,
            "write_access": rule.has_write_access,
            "xpath_constraint": rule.xpath_constraint,
            "has_xpath_constraint": rule.has_xpath_constraint,
            "roles": list(rule.roles),
            "role_count": len(rule.roles),
        }

    @staticmethod
    def _confidence(
        module_type,
        sensitive,
        rule,
    ) -> float:

        confidence = 0.70

        if module_type == "application":

            confidence += 0.08

        if sensitive:

            confidence += 0.08

        if rule.allow_delete:

            confidence += 0.05

        if rule.allow_create:

            confidence += 0.04

        if rule.has_xpath_constraint:

            confidence -= 0.10

        return round(
            min(
                max(
                    confidence,
                    0.0,
                ),
                0.99,
            ),
            2,
        )

    @staticmethod
    def _recommendation(rule, sensitivity) -> str:
        recommendations = FindingHelpersMixin._access_recommendations(rule)
        sensitive_note = FindingHelpersMixin._sensitivity_recommendation(sensitivity)
        if sensitive_note:
            recommendations.append(sensitive_note)
        if not recommendations:
            return "Review the entity security configuration and apply least-privilege access."
        return " ".join(recommendations)

    @staticmethod
    def _access_recommendations(rule) -> List[str]:
        recommendations = []
        if rule.allow_delete:
            recommendations.append("Restrict delete access to roles that explicitly require deletion.")
        if rule.allow_create:
            recommendations.append("Review which roles genuinely require create access.")
        if rule.has_write_access:
            recommendations.append("Replace broad ReadWrite access with the minimum required member permissions.")
        if not rule.has_xpath_constraint and (rule.allow_create or rule.allow_delete or rule.has_write_access):
            recommendations.append(
                "Consider an XPath constraint when users should only access records "
                "within their permitted business scope."
            )
        return recommendations

    @staticmethod
    def _sensitivity_recommendation(sensitivity) -> str:
        if not sensitivity["sensitive"] or not sensitivity["categories"]:
            return ""
        categories = ", ".join(sensitivity["categories"])
        return (
            f"Review sensitive data categories ({categories}) and ensure "
            "each role has only the minimum required access."
        )

    @staticmethod
    def _deduplicate(
        findings,
    ):

        unique = {}

        for finding in findings:

            key = (
                finding.get(
                    "rule_id"
                ),

                finding.get(
                    "entity"
                ),

                finding.get(
                    "microflow"
                ),

                finding.get(
                    "module"
                ),
            )

            existing = unique.get(
                key
            )

            if (
                existing is None
                or
                finding.get(
                    "score",
                    0,
                )
                >
                existing.get(
                    "score",
                    0,
                )
            ):

                unique[key] = finding

        return list(
            unique.values()
        )
