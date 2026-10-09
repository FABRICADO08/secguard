from typing import Any, Dict, List, Set

from backend.platforms.mendix.analyzer_checks import MendixAnalyzerChecks


class MendixSecurityAnalyzer(MendixAnalyzerChecks):
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