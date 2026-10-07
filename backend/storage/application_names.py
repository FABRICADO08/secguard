"""Application names chosen in SecGuard for GitHub-connected applications."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from backend.storage import scans

MAX_LENGTH = 80

_lock = threading.Lock()


def _path() -> Path:
    return scans.APPLICATIONS_DIR.parent / "application_names.json"


def clean_name(value: object) -> str:
    name = re.sub(r"\s+", " ", value).strip() if isinstance(value, str) else ""

    if not name:
        raise ValueError("The application name cannot be empty.")

    if len(name) > MAX_LENGTH:
        raise ValueError(f"The application name can have at most {MAX_LENGTH} characters.")

    return name


def _load() -> dict[str, str]:
    path = _path()

    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

    return {str(key): str(value) for key, value in data.items()} if isinstance(data, dict) else {}


def name_for(repository: str) -> str:
    return _load().get(repository.lower(), "")


def set_name(repository: str, name: str) -> None:
    with _lock:
        names = _load()
        names[repository.lower()] = name
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(names, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
