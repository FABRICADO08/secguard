from __future__ import annotations

from typing import Any, Dict, List

from .model import MendixModel
from .risk import RiskEngine
from .sensitivity import SensitivityDetector


class MendixSecurityRules:

    # ============================================================
    # TECHNICAL / FRAMEWORK MODULES
    # ============================================================

    TECHNICAL_MODULES = {
        "Administration",
        "CommunityCommons",
        "Constants",
        "DataImport",
        "DeeplinkCustomization",
        "Encryption",
        "Excel",
        "FileDocument",
        "MxID",
        "MxModelReflection",
        "NanoflowCommons",
        "OIDC",
        "OutlookMail",
        "System",
        "System_Administration",
        "WorkflowCommons",
    }

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        model: MendixModel,
    ):

        self.model = model

        self.sensitivity = (
            SensitivityDetector()
        )

        self.risk = RiskEngine()

    # ============================================================
    # MAIN
    # ============================================================

    def run(
        self,
    ) -> List[Dict[str, Any]]:

        findings = []

        findings.extend(
            self.entity_access_rules()
        )

        findings.extend(
            self.microflow_bypass_rules()
        )

        return self._deduplicate(
            findings
        )

    # ============================================================
    # ENTITY ACCESS
    # ============================================================

    def entity_access_rules(
        self,
    ) -> List[Dict[str, Any]]:

        findings = []

        for entity in self.model.entities:

            module_type = (
                self.classify_module(
                    entity.module
                )
            )

            sensitivity = (
                self.sensitivity.classify_entity(
                    entity
                )
            )

            for rule in entity.access_rules:

                write = bool(
                    rule.has_write_access
                )

                create = bool(
                    rule.allow_create
                )

                delete = bool(
                    rule.allow_delete
                )

                xpath = bool(
                    rule.has_xpath_constraint
                )

                role_count = len(
                    rule.roles
                )

                broad_roles = (
                    role_count >= 5
                )

                sensitive = bool(
                    sensitivity["sensitive"]
                )

                sensitivity_level = (
                    sensitivity[
                        "highest_severity"
                    ]
                )

                # ------------------------------------------------
                # Technical modules
                #
                # Framework entities are still parsed and analysed,
                # but their names alone must never create a
                # vulnerability.
                # ------------------------------------------------

                if module_type == "technical":

                    # Technical entity + generic CRUD access
                    # is not enough evidence.
                    #
                    # Only report when the entity contains
                    # genuinely sensitive attributes AND has
                    # dangerous modification rights.

                    if not sensitive:

                        continue

                    if not (
                        delete
                        or create
                    ):

                        continue

                    if sensitivity_level not in {
                        "high",
                        "critical",
                    }:

                        continue

                    if not broad_roles and not delete:

                        continue

                    risk = self.risk.calculate(
                        base_score=35,

                        sensitive=True,

                        sensitivity_severity=
                            sensitivity_level,

                        create=create,

                        delete=delete,

                        write=write,

                        xpath=xpath,

                        broad_roles=broad_roles,
                    )

                    if risk["score"] < 70:

                        continue

                # ------------------------------------------------
                # Application modules
                # ------------------------------------------------

                else:

                    # Generic ReadWrite is NOT a vulnerability.

                    # We need at least one stronger condition.
                    dangerous_write = (
                        write
                        and
                        (
                            create
                            or
                            delete
                        )
                    )

                    sensitive_modification = (
                        sensitive
                        and
                        (
                            write
                            or
                            create
                            or
                            delete
                        )
                    )

                    broad_dangerous_access = (
                        broad_roles
                        and
                        dangerous_write
                        and
                        not xpath
                    )

                    if not (
                        sensitive_modification
                        or
                        broad_dangerous_access
                    ):

                        continue

                    risk = self.risk.calculate(
                        base_score=25,

                        sensitive=sensitive,

                        sensitivity_severity=
                            sensitivity_level,

                        create=create,

                        delete=delete,

                        write=write,

                        xpath=xpath,

                        broad_roles=broad_roles,
                    )

                    if risk["score"] < 55:

                        continue

                findings.append(
                    self._entity_finding(
                        entity=entity,

                        rule=rule,

                        sensitivity=sensitivity,

                        risk=risk,

                        module_type=module_type,
                    )
                )

        return findings

    # ============================================================
    # MICROFLOW BYPASS
    # ============================================================

    def microflow_bypass_rules(
        self,
    ) -> List[Dict[str, Any]]:

        findings = []

        for microflow in self.model.microflows:

            if not microflow.bypasses_entity_access:

                continue

            module_type = (
                self.classify_module(
                    microflow.module
                )
            )

            # Do not report framework internals simply because
            # they bypass entity access.

            if module_type == "technical":

                continue

            role_count = len(
                microflow.allowed_module_roles
            )

            broad_roles = (
                role_count >= 5
            )

            risk = self.risk.calculate(
                base_score=40,

                bypasses_entity_access=True,

                broad_roles=broad_roles,
            )

            if risk["score"] < 60:

                continue

            findings.append(
                {
                    "rule_id":
                        "MXSEC-005",

                    "category":
                        "Access Control",

                    "severity":
                        risk["severity"],

                    "score":
                        risk["score"],

                    "confidence":
                        0.80,

                    "title":
                        "Microflow bypasses entity access",

                    "module":
                        microflow.module,

                    "module_type":
                        module_type,

                    "entity":
                        "",

                    "microflow":
                        (
                            microflow.qualified_name
                            or
                            microflow.name
                        ),

                    "description":
                        (
                            "The application microflow "
                            "does not apply entity access. "
                            "Authorization therefore needs "
                            "to be enforced explicitly."
                        ),

                    "evidence":
                        {
                            "allowed_roles":
                                microflow.allowed_module_roles,

                            "apply_entity_access":
                                microflow.apply_entity_access,
                        },

                    "recommendation":
                        (
                            "Review every entity operation "
                            "performed by this microflow. "
                            "Verify that the allowed roles "
                            "are appropriate and that "
                            "explicit authorization checks "
                            "protect sensitive operations."
                        ),
                }
            )

        return findings

    # ============================================================
    # MODULE CLASSIFICATION
    # ============================================================

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

    # ============================================================
    # FINDING CREATION
    # ============================================================

    def _entity_finding(
        self,
        entity,
        rule,
        sensitivity,
        risk,
        module_type,
    ) -> Dict[str, Any]:

        sensitive = (
            sensitivity["sensitive"]
        )

        if (
            sensitive
            and
            rule.allow_delete
        ):

            title = (
                "Sensitive entity allows deletion"
            )

        elif (
            sensitive
            and
            rule.has_write_access
            and
            rule.allow_create
            and
            not rule.has_xpath_constraint
        ):

            title = (
                "Sensitive entity has broad "
                "write access without row-level restriction"
            )

        elif (
            rule.allow_delete
            and
            rule.has_write_access
            and
            not rule.has_xpath_constraint
        ):

            title = (
                "Entity has broad delete/write access "
                "without row-level restriction"
            )

        elif (
            rule.allow_create
            and
            rule.has_write_access
            and
            not rule.has_xpath_constraint
        ):

            title = (
                "Entity has broad write access "
                "without row-level restriction"
            )

        else:

            title = (
                "Potential excessive entity access"
            )

        return {
            "rule_id":
                "MXSEC-101",

            "category":
                "Access Control",

            "severity":
                risk["severity"],

            "score":
                risk["score"],

            "confidence":
                self._confidence(
                    module_type,
                    sensitive,
                    rule,
                ),

            "title":
                title,

            "module":
                entity.module,

            "module_type":
                module_type,

            "entity":
                (
                    entity.qualified_name
                    or
                    entity.name
                ),

            "description":
                (
                    "The entity has a combination of "
                    "access-control conditions that may "
                    "permit excessive data access or "
                    "modification."
                ),

            "roles":
                list(
                    rule.roles
                ),

            "sensitivity":
                sensitivity,

            "evidence":
                {
                    "allow_create":
                        rule.allow_create,

                    "allow_delete":
                        rule.allow_delete,

                    "member_access":
                        rule.default_member_access_rights,

                    "write_access":
                        rule.has_write_access,

                    "xpath_constraint":
                        rule.xpath_constraint,

                    "has_xpath_constraint":
                        rule.has_xpath_constraint,

                    "roles":
                        list(
                            rule.roles
                        ),

                    "role_count":
                        len(
                            rule.roles
                        ),
                },

            "recommendation":
                self._recommendation(
                    rule,
                    sensitivity,
                ),
        }

    # ============================================================
    # CONFIDENCE
    # ============================================================

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

    # ============================================================
    # RECOMMENDATION
    # ============================================================

    @staticmethod
    def _recommendation(
        rule,
        sensitivity,
    ) -> str:

        recommendations = []

        if rule.allow_delete:

            recommendations.append(
                "Restrict delete access to roles "
                "that explicitly require deletion."
            )

        if rule.allow_create:

            recommendations.append(
                "Review which roles genuinely "
                "require create access."
            )

        if rule.has_write_access:

            recommendations.append(
                "Replace broad ReadWrite access "
                "with the minimum required member "
                "permissions."
            )

        if (
            not rule.has_xpath_constraint
            and
            (
                rule.allow_create
                or
                rule.allow_delete
                or
                rule.has_write_access
            )
        ):

            recommendations.append(
                "Consider an XPath constraint when "
                "users should only access records "
                "within their permitted business scope."
            )

        if sensitivity["sensitive"]:

            categories = (
                sensitivity[
                    "categories"
                ]
            )

            if categories:

                recommendations.append(
                    "Review sensitive data categories "
                    f"({', '.join(categories)}) and ensure "
                    "each role has only the minimum "
                    "required access."
                )

        if not recommendations:

            return (
                "Review the entity security configuration "
                "and apply least-privilege access."
            )

        return " ".join(
            recommendations
        )

    # ============================================================
    # DEDUPLICATION
    # ============================================================

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