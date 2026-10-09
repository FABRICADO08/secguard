from __future__ import annotations

from typing import Any, Dict, List

from .model import MendixModel
from .risk import RiskEngine
from .sensitivity import SensitivityDetector
from .security_rule_execution import EntityAccessRulesMixin
from .security_rule_findings import FindingHelpersMixin


class MendixSecurityRules(EntityAccessRulesMixin, FindingHelpersMixin):
    TECHNICAL_MODULES = {
        "Administration", "CommunityCommons", "Constants", "DataImport",
        "DeeplinkCustomization", "Encryption", "Excel", "FileDocument",
        "MxID", "MxModelReflection", "NanoflowCommons", "OIDC",
        "OutlookMail", "System", "System_Administration", "WorkflowCommons",
    }

    def __init__(
        self,
        model: MendixModel,
    ):
        self.model = model
        self.sensitivity = SensitivityDetector()
        self.risk = RiskEngine()

    def run(self) -> List[Dict[str, Any]]:
        findings = []
        findings.extend(self.entity_access_rules())
        findings.extend(self.microflow_bypass_rules())
        return self._deduplicate(findings)
