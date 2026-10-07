"""Application names chosen in SecGuard for GitHub-connected applications."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from backend.storage import db
from backend.storage import scans

MAX_LENGTH = 80

_lock = threading.Lock()


def _path() -> Path:
    return scans.APPLICATIONS_DIR.parent / "application_names.json"


EMPTY = "The application name cannot be empty."
TOO_LONG = f"The application name can have at most {MAX_LENGTH} characters."


def name_problem(value: object) -> str:
    """Why ``value`` cannot be an application name, or "" when it can."""

    name = normalise(value)

    if not name:
        return EMPTY

    return TOO_LONG if len(name) > MAX_LENGTH else ""


def normalise(value: object) -> str:
    return re.sub(r"\s+", " ", value).strip() if isinstance(value, str) else ""


def clean_name(value: object) -> str:
    problem = name_problem(value)

    if problem:
        raise ValueError(problem)

    return normalise(value)


def _load() -> dict[str, str]:
    if db.use_database():
        return db.all_names()

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
        if db.use_database():
            db.set_name(repository, name)

            return

        names = _load()
        names[repository.lower()] = name
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(names, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
