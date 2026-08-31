from typing import Any, Dict, List, Set


class MendixSecurityAnalyzer:
    """
    Security analyzer for parsed Mendix models.

    The analyzer intentionally produces evidence-based findings.
    It does not treat every entity with Write access as automatically
    critical. Severity is increased when the entity/attributes indicate
    sensitive information or dangerous operations.
    """

    SENSITIVE_KEYWORDS = {
        "authentication": {
            "token",
            "accesstoken",
            "refreshtoken",
            "authentication",
            "auth",
            "oauth",
            "session",
            "login",
            "claim",
            "codechallenge",
            "authorization",
        },
        "credential": {
            "password",
            "passwd",
            "secret",
            "credential",
            "privatekey",
            "apikey",
            "api_key",
            "clientsecret",
            "client_secret",
        },
        "personal": {
            "firstname",
            "first_name",
            "lastname",
            "last_name",
            "fullname",
            "full_name",
            "email",
            "emailaddress",
            "email_address",
            "phone",
            "phonenumber",
            "phone_number",
            "address",
            "dateofbirth",
            "date_of_birth",
            "dob",
        },
        "identity": {
            "username",
            "userid",
            "user_id",
            "userid",
            "identity",
            "employeeid",
            "employee_id",
            "userid",
            "guid",
        },
        "financial": {
            "accountnumber",
            "account_number",
            "bankaccount",
            "bank_account",
            "creditcard",
            "credit_card",
            "iban",
            "swift",
            "salary",
            "payment",
        },
    }

    def __init__(self, model):
        self.model = model
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run all Mendix security checks.
        """

        self.findings = []

        self._check_entity_access()
        self._check_sensitive_entities()
        self._check_sensitive_attributes()
        self._check_associations()

        return self.findings

    # ------------------------------------------------------------------
    # GENERAL HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _get(obj, name, default=None):
        """
        Safely retrieve a property from either a dataclass/object or dict.
        """

        if obj is None:
            return default

        if isinstance(obj, dict):
            return obj.get(name, default)

        return getattr(obj, name, default)

    @staticmethod
    def _normalise(value) -> str:
        if value is None:
            return ""

        return str(value).strip().lower()

    @staticmethod
    def _qualified_name(entity) -> str:
        return (
            MendixSecurityAnalyzer._get(entity, "qualified_name")
            or MendixSecurityAnalyzer._get(entity, "name")
            or ""
        )

    @staticmethod
    def _attribute_name(attribute) -> str:
        return (
            MendixSecurityAnalyzer._get(attribute, "qualified_name")
            or MendixSecurityAnalyzer._get(attribute, "name")
            or ""
        )

    @staticmethod
    def _role_names(rule) -> List[str]:
        roles = (
            MendixSecurityAnalyzer._get(rule, "module_roles")
            or MendixSecurityAnalyzer._get(rule, "roles")
            or []
        )

        if isinstance(roles, str):
            return [roles]

        return [str(role) for role in roles]

    @staticmethod
    def _access_rights(rule) -> str:
        """
        Mendix dump uses defaultMemberAccessRights.

        Older versions of our parser called this
        default_member_access. Support both names so the analyzer
        remains backward compatible.
        """

        value = (
            MendixSecurityAnalyzer._get(
                rule,
                "default_member_access_rights",
            )
        )

        if value is None:
            value = MendixSecurityAnalyzer._get(
                rule,
                "default_member_access",
            )

        return str(value or "None")

    @staticmethod
    def _member_accesses(rule):
        accesses = (
            MendixSecurityAnalyzer._get(rule, "member_accesses")
            or MendixSecurityAnalyzer._get(rule, "memberAccesses")
            or []
        )

        return accesses

    @staticmethod
    def _allow_create(rule) -> bool:
        return bool(
            MendixSecurityAnalyzer._get(
                rule,
                "allow_create",
                MendixSecurityAnalyzer._get(
                    rule,
                    "allowCreate",
                    False,
                ),
            )
        )

    @staticmethod
    def _allow_delete(rule) -> bool:
        return bool(
            MendixSecurityAnalyzer._get(
                rule,
                "allow_delete",
                MendixSecurityAnalyzer._get(
                    rule,
                    "allowDelete",
                    False,
                ),
            )
        )

    @staticmethod
    def _xpath(rule) -> str:
        return str(
            MendixSecurityAnalyzer._get(
                rule,
                "xpath_constraint",
                MendixSecurityAnalyzer._get(
                    rule,
                    "xPathConstraint",
                    "",
                ),
            )
            or ""
        ).strip()

    # ------------------------------------------------------------------
    # ENTITY HELPERS
    # ------------------------------------------------------------------

    def _entities(self):
        return (
            self._get(self.model, "entities", [])
            or []
        )

    def _entity_attributes(self, entity):
        return (
            self._get(entity, "attributes", [])
            or []
        )

    def _entity_access_rules(self, entity):
        return (
            self._get(entity, "access_rules", [])
            or self._get(entity, "accessRules", [])
            or []
        )

    # ------------------------------------------------------------------
    # SENSITIVITY DETECTION
    # ------------------------------------------------------------------

    def _detect_sensitive_categories(self, entity) -> Set[str]:
        """
        Detect sensitivity from both entity and attribute names.

        This is deliberately keyword-based for now. Later we can add
        richer semantic classification.
        """

        categories: Set[str] = set()

        entity_name = self._normalise(
            self._qualified_name(entity)
        )

        attribute_names = [
            self._normalise(
                self._attribute_name(attribute)
            )
            for attribute in self._entity_attributes(entity)
        ]

        combined = entity_name + " " + " ".join(attribute_names)

        compact = (
            combined
            .replace(".", " ")
            .replace("-", " ")
            .replace("_", " ")
        )

        tokens = set(compact.split())

        for category, keywords in self.SENSITIVE_KEYWORDS.items():

            for keyword in keywords:

                keyword_normalised = (
                    keyword.lower()
                    .replace("_", " ")
                )

                if keyword_normalised in compact:
                    categories.add(category)
                    break

                if keyword_normalised in tokens:
                    categories.add(category)
                    break

        return categories

    def _sensitive_attributes(self, entity) -> Dict[str, Set[str]]:
        """
        Return sensitive attributes and their categories.
        """

        result: Dict[str, Set[str]] = {}

        entity_name = self._normalise(
            self._qualified_name(entity)
        )

        for attribute in self._entity_attributes(entity):

            name = self._attribute_name(attribute)

            searchable = (
                entity_name
                + " "
                + self._normalise(name)
            )

            searchable = (
                searchable
                .replace(".", " ")
                .replace("-", " ")
                .replace("_", " ")
            )

            tokens = set(searchable.split())

            categories: Set[str] = set()

            for category, keywords in self.SENSITIVE_KEYWORDS.items():

                for keyword in keywords:

                    keyword_normalised = (
                        keyword.lower()
                        .replace("_", " ")
                    )

                    if (
                        keyword_normalised in searchable
                        or keyword_normalised in tokens
                    ):
                        categories.add(category)
                        break

            if categories:
                result[name] = categories

        return result

    # ------------------------------------------------------------------
    # MXSEC-101
    # ------------------------------------------------------------------

    def _check_entity_access(self):

        for entity in self._entities():

            entity_name = self._qualified_name(entity)

            if not entity_name:
                continue

            categories = self._detect_sensitive_categories(
                entity
            )

            for rule in self._entity_access_rules(entity):

                roles = self._role_names(rule)

                allow_create = self._allow_create(rule)
                allow_delete = self._allow_delete(rule)

                xpath = self._xpath(rule)

                member_accesses = self._member_accesses(rule)

                broad_member_access = False

                for member in member_accesses:

                    rights = self._normalise(
                        self._get(
                            member,
                            "access_rights",
                            self._get(
                                member,
                                "accessRights",
                                "",
                            ),
                        )
                    )

                    if rights in {
                        "readwrite",
                        "readwrite",
                        "write",
                    }:
                        broad_member_access = True
                        break

                if not broad_member_access:

                    default_access = self._normalise(
                        self._access_rights(rule)
                    )

                    if default_access in {
                        "readwrite",
                        "write",
                    }:
                        broad_member_access = True

                if not broad_member_access and not allow_delete:
                    continue

                sensitive = bool(categories)

                if sensitive and allow_delete:
                    severity = "critical"
                    title = "Sensitive entity allows deletion"

                elif sensitive and broad_member_access:
                    severity = "critical"
                    title = (
                        "Sensitive entity has broad write access "
                        "without row-level restriction"
                    )

                elif allow_delete and not xpath:
                    severity = "high"
                    title = (
                        "Entity has broad delete/write access "
                        "without row-level restriction"
                    )

                elif broad_member_access and not xpath:
                    severity = "high"
                    title = (
                        "Entity has broad write access "
                        "without row-level restriction"
                    )

                else:
                    continue

                recommendation_parts = []

                if allow_delete:
                    recommendation_parts.append(
                        "Restrict delete access to roles that "
                        "explicitly require deletion."
                    )

                if allow_create:
                    recommendation_parts.append(
                        "Review which roles genuinely require "
                        "create access."
                    )

                if broad_member_access:
                    recommendation_parts.append(
                        "Replace broad ReadWrite access with the "
                        "minimum required member permissions."
                    )

                if not xpath:
                    recommendation_parts.append(
                        "Consider an XPath constraint when users "
                        "should only access records within their "
                        "permitted business scope."
                    )

                if categories:
                    category_text = ", ".join(
                        sorted(categories)
                    )

                    recommendation_parts.append(
                        "Review sensitive data categories "
                        f"({category_text}) and ensure each role "
                        "has only the minimum required access."
                    )

                finding = {
                    "rule_id": "MXSEC-101",
                    "severity": severity,
                    "title": title,
                    "entity": entity_name,
                    "module": self._module_from_entity(
                        entity_name
                    ),
                    "roles": roles,
                    "access": {
                        "create": allow_create,
                        "delete": allow_delete,
                        "default_member_access": (
                            self._access_rights(rule)
                        ),
                        "member_accesses": [
                            self._member_access_to_dict(
                                member
                            )
                            for member in member_accesses
                        ],
                    },
                    "xpath": xpath,
                    "sensitive": sensitive,
                    "sensitive_categories": sorted(
                        categories
                    ),
                    "evidence": {
                        "create_allowed": allow_create,
                        "delete_allowed": allow_delete,
                        "broad_member_access": (
                            broad_member_access
                        ),
                        "xpath_constraint_present": bool(
                            xpath
                        ),
                        "roles": roles,
                    },
                    "risk": self._risk_for_entity_access(
                        sensitive=sensitive,
                        allow_create=allow_create,
                        allow_delete=allow_delete,
                        broad_member_access=(
                            broad_member_access
                        ),
                        xpath=xpath,
                    ),
                    "recommendation": " ".join(
                        recommendation_parts
                    ),
                }

                self.findings.append(finding)

    # ------------------------------------------------------------------
    # MXSEC-102
    # ------------------------------------------------------------------

    def _check_sensitive_entities(self):

        for entity in self._entities():

            entity_name = self._qualified_name(entity)

            if not entity_name:
                continue

            categories = self._detect_sensitive_categories(
                entity
            )

            if not categories:
                continue

            sensitive_attributes = (
                self._sensitive_attributes(entity)
            )

            rules = self._entity_access_rules(entity)

            if not rules:
                self.findings.append({
                    "rule_id": "MXSEC-102",
                    "severity": "high",
                    "title": (
                        "Sensitive entity has no explicit "
                        "access rules"
                    ),
                    "entity": entity_name,
                    "module": self._module_from_entity(
                        entity_name
                    ),
                    "roles": [],
                    "access": {},
                    "xpath": "",
                    "sensitive": True,
                    "sensitive_categories": sorted(
                        categories
                    ),
                    "attributes": list(
                        sensitive_attributes.keys()
                    ),
                    "evidence": {
                        "access_rule_count": 0,
                    },
                    "risk": (
                        "The model contains an entity associated "
                        "with sensitive information but no explicit "
                        "entity access rules were detected."
                    ),
                    "recommendation": (
                        "Define explicit entity access rules and "
                        "verify that only the minimum required "
                        "module roles can access the sensitive data."
                    ),
                })

    # ------------------------------------------------------------------
    # MXSEC-106
    # ------------------------------------------------------------------

    def _check_sensitive_attributes(self):

        for entity in self._entities():

            entity_name = self._qualified_name(entity)

            sensitive_attributes = (
                self._sensitive_attributes(entity)
            )

            if not sensitive_attributes:
                continue

            rules = self._entity_access_rules(entity)

            for attribute_name, categories in (
                sensitive_attributes.items()
            ):

                risky_roles = []

                for rule in rules:

                    roles = self._role_names(rule)

                    for member in self._member_accesses(rule):

                        member_attribute = (
                            self._get(
                                member,
                                "attribute",
                                "",
                            )
                        )

                        if (
                            member_attribute
                            and (
                                member_attribute
                                == attribute_name
                            )
                        ):
                            rights = self._normalise(
                                self._get(
                                    member,
                                    "access_rights",
                                    self._get(
                                        member,
                                        "accessRights",
                                        "",
                                    ),
                                )
                            )

                            if rights in {
                                "readwrite",
                                "write",
                                "read",
                                "readonly",
                            }:
                                risky_roles.extend(
                                    roles
                                )

                risky_roles = sorted(
                    set(risky_roles)
                )

                if not risky_roles:
                    continue

                severity = "critical"

                category_text = ", ".join(
                    sorted(categories)
                )

                self.findings.append({
                    "rule_id": "MXSEC-106",
                    "severity": severity,
                    "title": (
                        "Sensitive attribute is accessible "
                        "to application roles"
                    ),
                    "entity": entity_name,
                    "module": self._module_from_entity(
                        entity_name
                    ),
                    "roles": risky_roles,
                    "attributes": [
                        {
                            "name": attribute_name,
                            "sensitive_categories": sorted(
                                categories
                            ),
                        }
                    ],
                    "access": {
                        "roles_with_access": risky_roles,
                    },
                    "xpath": "",
                    "sensitive": True,
                    "sensitive_categories": sorted(
                        categories
                    ),
                    "evidence": {
                        "attribute": attribute_name,
                        "categories": sorted(
                            categories
                        ),
                        "roles": risky_roles,
                    },
                    "risk": (
                        f"The attribute '{attribute_name}' "
                        f"appears to contain {category_text} "
                        "information and is accessible through "
                        "one or more module roles."
                    ),
                    "recommendation": (
                        "Review whether every listed role needs "
                        "access to this attribute. Remove "
                        "unnecessary Read/Write permissions and "
                        "apply least-privilege access."
                    ),
                })

    # ------------------------------------------------------------------
    # ASSOCIATION CHECKS
    # ------------------------------------------------------------------

    def _check_associations(self):

        associations = (
            self._get(
                self.model,
                "associations",
                [],
            )
            or []
        )

        for association in associations:

            name = (
                self._get(
                    association,
                    "qualified_name",
                )
                or self._get(
                    association,
                    "name",
                )
                or ""
            )

            if not name:
                continue

            delete_behavior = self._get(
                association,
                "delete_behavior",
                self._get(
                    association,
                    "deleteBehavior",
                    None,
                ),
            )

            # Parsed associations carry the behaviour as flat fields
            # while raw dump nodes nest it in a delete behaviour object.
            behavior = delete_behavior or association

            parent_behavior = self._get(
                behavior,
                "parent_delete_behavior",
                self._get(
                    behavior,
                    "parentDeleteBehavior",
                    "",
                ),
            )

            child_behavior = self._get(
                behavior,
                "child_delete_behavior",
                self._get(
                    behavior,
                    "childDeleteBehavior",
                    "",
                ),
            )

            dangerous_values = {
                "DeleteMeAndReferences",
                "DeleteMeButKeepReferences",
            }

            if (
                parent_behavior in dangerous_values
                or child_behavior in dangerous_values
            ):
                self.findings.append({
                    "rule_id": "MXSEC-401",
                    "severity": "medium",
                    "title": (
                        "Association has cascading delete "
                        "behaviour"
                    ),
                    "association": name,
                    "roles": [],
                    "access": {},
                    "xpath": "",
                    "sensitive": False,
                    "sensitive_categories": [],
                    "evidence": {
                        "parent_delete_behavior": (
                            parent_behavior
                        ),
                        "child_delete_behavior": (
                            child_behavior
                        ),
                    },
                    "risk": (
                        "Deleting one object may cause related "
                        "objects to be deleted or references "
                        "to be altered automatically."
                    ),
                    "recommendation": (
                        "Review the association delete behaviour "
                        "and confirm that cascading deletion is "
                        "required for the application's business "
                        "logic."
                    ),
                })

    # ------------------------------------------------------------------
    # FORMATTING HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _module_from_entity(entity_name: str) -> str:

        if "." not in entity_name:
            return entity_name

        return entity_name.split(".", 1)[0]

    @staticmethod
    def _member_access_to_dict(member) -> Dict[str, Any]:

        return {
            "attribute": (
                MendixSecurityAnalyzer._get(
                    member,
                    "attribute",
                    "",
                )
            ),
            "association": (
                MendixSecurityAnalyzer._get(
                    member,
                    "association",
                    "",
                )
            ),
            "access_rights": (
                MendixSecurityAnalyzer._get(
                    member,
                    "access_rights",
                    MendixSecurityAnalyzer._get(
                        member,
                        "accessRights",
                        "",
                    ),
                )
            ),
        }

    @staticmethod
    def _risk_for_entity_access(
        *,
        sensitive: bool,
        allow_create: bool,
        allow_delete: bool,
        broad_member_access: bool,
        xpath: str,
    ) -> str:

        if sensitive and allow_delete:
            return (
                "A role with this access can delete records "
                "associated with sensitive information. "
                "The impact is increased when broad member "
                "access is also present."
            )

        if sensitive and broad_member_access:
            return (
                "A role may read and modify sensitive information "
                "through broad member permissions."
            )

        if allow_delete and not xpath:
            return (
                "Users with the affected role may delete entity "
                "records without a row-level XPath restriction."
            )

        if broad_member_access and not xpath:
            return (
                "Users with the affected role may modify entity "
                "records without a row-level XPath restriction."
            )

        return (
            "The entity has potentially broader access than "
            "required by least-privilege principles."
        )