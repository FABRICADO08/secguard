"""Remediation decisions on findings, kept per system so they survive later scans."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from backend.storage import db, scans

_lock = threading.Lock()


def _path() -> Path:
    return scans.APPLICATIONS_DIR.parent / "finding_triage.json"


def _key(system: str, finding: str) -> str:
    return f"{system}\n{finding}"


def _load_file() -> dict[str, dict[str, Any]]:
    path = _path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_system(system: str) -> dict[str, dict[str, Any]]:
    """Triage records of one system, keyed by finding identity."""
    if db.use_database():
        return db.load_triage(system)
    prefix = f"{system}\n"
    return {key[len(prefix):]: value for key, value in _load_file().items() if key.startswith(prefix)}


def update_record(
    system: str,
    finding: str,
    change: Callable[[dict[str, Any]], tuple[dict[str, Any] | None, str]],
) -> tuple[dict[str, Any] | None, str]:
    """Apply ``change`` to one finding's record atomically; a ``None`` record leaves it untouched."""
    if db.use_database():
        return db.update_triage(system, finding, change)
    with _lock:
        records = _load_file()
        record, problem = change(records.get(_key(system, finding), {}))
        if record is None:
            return None, problem
        records[_key(system, finding)] = record
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
        return record, problem
