from __future__ import annotations

from typing import Any, Dict, List, Optional

class ParserHelpersMixin:
    @staticmethod
    def _is_microflow_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Microflows$Microflow"
            or
            node_type.endswith(
                "Microflows$Microflow"
            )
        )

    @staticmethod
    def _is_page_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Pages$Page"
            or
            node_type.endswith(
                "Pages$Page"
            )
        )

    @staticmethod
    def _is_module_role_type(
        node_type: str,
    ) -> bool:

        return (
            node_type
            ==
            "Security$ModuleRole"
            or
            node_type.endswith(
                "Security$ModuleRole"
            )
        )

    @staticmethod
    def _name(
        node: Dict[str, Any],
    ) -> str:

        return str(
            node.get(
                "name",
                "",
            )
            or
            ""
        )

    @staticmethod
    def _qualified_name(
        node: Dict[str, Any],
    ) -> str:

        return str(
            node.get(
                "$QualifiedName",
                "",
            )
            or
            node.get(
                "qualifiedName",
                "",
            )
            or
            ""
        )

    @staticmethod
    def _module_from_name(
        qualified_name: str,
    ) -> str:

        if not qualified_name:

            return ""

        parts = (
            qualified_name.split(
                "."
            )
        )

        if len(parts) < 2:

            return ""

        return parts[0]

    @classmethod
    def _reference_name(
        cls,
        value: Any,
    ) -> str:

        if value is None:

            return ""

        if isinstance(
            value,
            str,
        ):

            return value

        if isinstance(
            value,
            dict,
        ):

            return str(
                value.get(
                    "$QualifiedName",
                    "",
                )
                or
                value.get(
                    "qualifiedName",
                    "",
                )
                or
                value.get(
                    "name",
                    "",
                )
                or
                value.get(
                    "$Ref",
                    "",
                )
                or
                ""
            )

        return str(
            value
        )

    @staticmethod
    def _extract_attribute_type(
        node: Dict[str, Any],
    ) -> str:

        attribute_type = node.get(
            "type"
        )

        if isinstance(
            attribute_type,
            dict,
        ):

            return str(
                attribute_type.get(
                    "$Type",
                    "",
                )
                or
                ""
            )

        return str(
            attribute_type
            or
            ""
        )

    @staticmethod
    def _extract_length(
        node: Dict[str, Any],
    ) -> Optional[int]:

        attribute_type = node.get(
            "type"
        )

        if not isinstance(
            attribute_type,
            dict,
        ):

            return None

        length = attribute_type.get(
            "length"
        )

        if length is None:

            return None

        try:

            return int(
                length
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

    @staticmethod
    def _find_boolean(
        node: Dict[str, Any],
        keys: List[str],
        default: bool,
    ) -> bool:

        for key in keys:

            if key in node:

                return bool(
                    node[key]
                )

        return default

    @classmethod
    def _find_string_list(
        cls,
        node: Dict[str, Any],
        keys: List[str],
    ) -> List[str]:

        for key in keys:

            value = node.get(
                key
            )

            if not isinstance(
                value,
                list,
            ):

                continue

            result = []

            for item in value:

                reference = (
                    cls._reference_name(
                        item
                    )
                )

                if reference:

                    result.append(
                        reference
                    )

            return result

        return []

    @staticmethod
    def _member_access_has(
        members: List[Dict[str, Any]],
        permission: str,
    ) -> bool:

        permission = (
            permission.lower()
        )

        for member in members:

            rights = str(
                member.get(
                    "access_rights",
                    "",
                )
                or
                ""
            ).lower()

            if permission in rights:

                return True

        return False

    @staticmethod
    def _construct(
        cls,
        values: Dict[str, Any],
    ):

        """
        Construct model classes while remaining compatible with
        the current model.py implementation.

        First try normal keyword construction.

        If the dataclass/model does not accept those arguments,
        create the object and assign what it supports.
        """

        try:

            return cls(
                **values
            )

        except TypeError:

            try:

                obj = cls()

            except TypeError:

                obj = cls.__new__(
                    cls
                )

            for key, value in values.items():

                try:

                    setattr(
                        obj,
                        key,
                        value,
                    )

                except (
                    AttributeError,
                    TypeError,
                ):

                    pass

            return obj

    @staticmethod
    def _set_if_possible(
        obj: Any,
        name: str,
        value: Any,
    ) -> None:

        try:

            setattr(
                obj,
                name,
                value,
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass

    @staticmethod
    def _ensure_list(
        obj: Any,
        name: str,
    ) -> None:

        current = getattr(
            obj,
            name,
            None,
        )

        if isinstance(
            current,
            list,
        ):

            return

        try:

            setattr(
                obj,
                name,
                [],
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass

    @staticmethod
    def _append_unique(
        collection: list,
        value: Any,
    ) -> None:

        if value not in collection:

            collection.append(
                value
            )
