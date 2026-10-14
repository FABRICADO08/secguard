from __future__ import annotations

from typing import Any, Dict, List

from .risk import RiskInputs


class EntityAccessRulesMixin:
    def entity_access_rules(self) -> List[Dict[str, Any]]:
        findings = []
        for entity in self.model.entities:
            module_type = self.classify_module(entity.module)
            sensitivity = self.sensitivity.classify_entity(entity)
            for rule in entity.access_rules:
                finding = self._entity_access_finding(
                    entity, rule, module_type, sensitivity
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    def _entity_access_finding(self, entity, rule, module_type, sensitivity):
        risk = self._entity_access_risk(rule, module_type, sensitivity)
        if risk is None:
            return None
        return self._entity_finding(entity, rule, sensitivity, risk, module_type)

    def _entity_access_risk(self, rule, module_type, sensitivity):
        access = {
            "write": bool(rule.has_write_access),
            "create": bool(rule.allow_create),
            "delete": bool(rule.allow_delete),
            "xpath": bool(rule.has_xpath_constraint),
            "broad_roles": len(rule.roles) >= 5,
        }
        if module_type == "technical":
            return self._technical_entity_risk(access, sensitivity)
        return self._application_entity_risk(access, sensitivity)

    @staticmethod
    def _technical_rule_qualifies(access, sensitivity) -> bool:
        if not sensitivity["sensitive"] or not (access["delete"] or access["create"]):
            return False
        if sensitivity["highest_severity"] not in {"high", "critical"}:
            return False
        return access["broad_roles"] or access["delete"]

    def _technical_entity_risk(self, access, sensitivity):
        if not self._technical_rule_qualifies(access, sensitivity):
            return None
        inputs = RiskInputs(
            base_score=35, sensitive=True,
            sensitivity_severity=sensitivity["highest_severity"], **access,
        )
        return self._risk_above(inputs, 70)

    def _application_entity_risk(self, access, sensitivity):
        sensitive = bool(sensitivity["sensitive"])
        modifies = access["write"] or access["create"] or access["delete"]
        dangerous_write = access["write"] and (access["create"] or access["delete"])
        broad_dangerous_access = (
            access["broad_roles"] and dangerous_write and not access["xpath"]
        )
        if not ((sensitive and modifies) or broad_dangerous_access):
            return None
        inputs = RiskInputs(
            base_score=25, sensitive=sensitive,
            sensitivity_severity=sensitivity["highest_severity"], **access,
        )
        return self._risk_above(inputs, 55)

    def _risk_above(self, inputs: RiskInputs, minimum: int):
        risk = self.risk.calculate(inputs)
        return risk if risk["score"] >= minimum else None

    def microflow_bypass_rules(self) -> List[Dict[str, Any]]:
        findings = []
        for microflow in self.model.microflows:
            if not microflow.bypasses_entity_access:
                continue
            finding = self._microflow_bypass_finding(microflow)
            if finding is not None:
                findings.append(finding)
        return findings

    def _microflow_bypass_finding(self, microflow):
        module_type = self.classify_module(microflow.module)
        if module_type == "technical":
            return None
        broad_roles = len(microflow.allowed_module_roles) >= 5
        risk = self.risk.calculate(RiskInputs(
            base_score=40, broad_roles=broad_roles,
            bypasses_entity_access=True,
        ))
        if risk["score"] < 60:
            return None
        return {
            "rule_id": "MXSEC-005",
            "category": "Access Control",
            "severity": risk["severity"],
            "score": risk["score"],
            "confidence": 0.80,
            "title": "Microflow bypasses entity access",
            "module": microflow.module,
            "module_type": module_type,
            "entity": "",
            "microflow": microflow.qualified_name or microflow.name,
            "description": (
                "The application microflow does not apply entity access. "
                "Authorization therefore needs to be enforced explicitly."
            ),
            "evidence": {
                "allowed_roles": microflow.allowed_module_roles,
                "apply_entity_access": microflow.apply_entity_access,
            },
            "recommendation": (
                "Review every entity operation performed by this microflow. "
                "Verify that the allowed roles are appropriate and that "
                "explicit authorization checks protect sensitive operations."
            ),
        }
