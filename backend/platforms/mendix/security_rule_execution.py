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
        write = bool(rule.has_write_access)
        create = bool(rule.allow_create)
        delete = bool(rule.allow_delete)
        xpath = bool(rule.has_xpath_constraint)
        broad_roles = len(rule.roles) >= 5
        sensitive = bool(sensitivity["sensitive"])
        sensitivity_level = sensitivity["highest_severity"]

        if module_type == "technical":
            if not sensitive or not (delete or create):
                return None
            if sensitivity_level not in {"high", "critical"}:
                return None
            if not broad_roles and not delete:
                return None
            inputs = RiskInputs(
                base_score=35, sensitive=True,
                sensitivity_severity=sensitivity_level, create=create,
                delete=delete, write=write, xpath=xpath, broad_roles=broad_roles,
            )
            return self._risk_above(inputs, 70)

        dangerous_write = write and (create or delete)
        sensitive_modification = sensitive and (write or create or delete)
        broad_dangerous_access = broad_roles and dangerous_write and not xpath
        if not (sensitive_modification or broad_dangerous_access):
            return None
        inputs = RiskInputs(
            base_score=25, sensitive=sensitive,
            sensitivity_severity=sensitivity_level, create=create,
            delete=delete, write=write, xpath=xpath, broad_roles=broad_roles,
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
