from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .model import MendixModel
from .parser_walker import ParserWalkerMixin
from .parser_entities import ParserEntitiesMixin
from .parser_access import ParserAccessMixin
from .parser_objects import ParserObjectsMixin
from .parser_resolution import ParserResolutionMixin
from .parser_helpers import ParserHelpersMixin


class MendixModelParser(
    ParserWalkerMixin,
    ParserEntitiesMixin,
    ParserAccessMixin,
    ParserObjectsMixin,
    ParserResolutionMixin,
    ParserHelpersMixin,
):
    """Parser for Mendix dump-mpr JSON."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.model = MendixModel()
        for index_name in (
            "entities_by_name", "entities_by_id", "attributes_by_name",
            "associations_by_name", "microflows_by_name", "pages_by_name",
            "modules_by_name", "module_roles_by_name", "access_rules_by_id",
        ):
            setattr(self, index_name, {})

    @classmethod
    def from_file(
        cls,
        path: Path | str,
    ) -> "MendixModelParser":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file does not exist: {path}")
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError("Mendix model JSON root must be an object.")
        return cls(data)

    def parse(self) -> MendixModel:
        self._parse_modules()
        self._walk_model(self.data)
        self._parse_associations()
        self._resolve_references()
        return self.model


Parser = MendixModelParser
