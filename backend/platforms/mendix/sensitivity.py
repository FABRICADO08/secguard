from __future__ import annotations

import re
from typing import Dict, List

from .model import Attribute, Entity


class SensitivityDetector:

    PATTERNS = {
        "credential": [
            r"password",
            r"passwd",
            r"passcode",
            r"secret",
            r"privatekey",
            r"credential",
        ],

        "authentication": [
            r"token",
            r"access.?token",
            r"refresh.?token",
            r"api.?key",
            r"client.?secret",
            r"session",
        ],

        "financial": [
            r"bank.?account",
            r"account.?number",
            r"credit.?card",
            r"card.?number",
            r"iban",
            r"swift",
            r"salary",
            r"payment",
            r"invoice",
        ],

        "identity": [
            r"id.?number",
            r"identity",
            r"national.?id",
            r"passport",
            r"tax.?number",
            r"employee.?number",
        ],

        "personal": [
            r"email",
            r"phone",
            r"mobile",
            r"address",
            r"date.?of.?birth",
            r"\bdob\b",
            r"first.?name",
            r"last.?name",
            r"full.?name",
        ],
    }

    SEVERITY = {
        "credential": "critical",
        "authentication": "high",
        "financial": "high",
        "identity": "high",
        "personal": "medium",
    }

    def classify_attribute(
        self,
        attribute: Attribute,
    ) -> List[str]:

        return self._classify(
            attribute.name
        )

    def classify_entity(
        self,
        entity: Entity,
    ) -> Dict:

        categories = set()

        sensitive_attributes = []

        # ----------------------------------------------------
        # Attribute analysis
        # ----------------------------------------------------

        for attribute in entity.attributes:

            attribute_categories = (
                self.classify_attribute(
                    attribute
                )
            )

            if not attribute_categories:
                continue

            categories.update(
                attribute_categories
            )

            sensitive_attributes.append(
                {
                    "name":
                        attribute.name,

                    "qualified_name":
                        attribute.qualified_name,

                    "categories":
                        attribute_categories,
                }
            )

        # ----------------------------------------------------
        # Entity name analysis
        # ----------------------------------------------------

        entity_categories = self._classify(
            entity.name
        )

        categories.update(
            entity_categories
        )

        return {
            "entity":
                entity.qualified_name
                or entity.name,

            "categories":
                sorted(categories),

            "sensitive":
                bool(
                    sensitive_attributes
                    or entity_categories
                ),

            "attributes":
                sensitive_attributes,

            "entity_name_categories":
                entity_categories,

            "highest_severity":
                self._highest_severity(
                    categories
                ),
        }

    def analyze_model(
        self,
        entities: List[Entity],
    ) -> List[Dict]:

        results = []

        for entity in entities:

            result = self.classify_entity(
                entity
            )

            if result["sensitive"]:

                results.append(
                    result
                )

        return results

    def _classify(
        self,
        value: str,
    ) -> List[str]:

        value = self._normalize(
            value
        )

        categories = []

        for category, patterns in (
            self.PATTERNS.items()
        ):

            for pattern in patterns:

                if re.search(
                    pattern,
                    value,
                    re.IGNORECASE,
                ):

                    categories.append(
                        category
                    )

                    break

        return categories

    @staticmethod
    def _normalize(
        value: str,
    ) -> str:

        return re.sub(
            r"[\s\-_]+",
            "",
            str(value or "").lower(),
        )

    def _highest_severity(
        self,
        categories,
    ) -> str:

        priority = [
            "critical",
            "high",
            "medium",
            "low",
        ]

        detected = [
            self.SEVERITY[category]
            for category in categories
            if category in self.SEVERITY
        ]

        for severity in priority:

            if severity in detected:

                return severity

        return "low"