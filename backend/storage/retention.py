"""Delete scans older than the retention window, always keeping each system's newest scan."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.config import settings
from backend.storage import scans


def _system(application: dict[str, Any]) -> str:
    key = application.get("repository") or application.get("url") or application.get("requested_url")
    return str(key or application.get("id") or "").lower()


def _stamp(application: dict[str, Any]) -> str:
    return str(application.get("updated_at") or application.get("created_at") or "")


def expired(applications: list[dict[str, Any]], cutoff: str) -> list[str]:
    """IDs of scans last updated before ``cutoff`` that are not their system's newest."""
    newest: dict[str, str] = {}
    for application in sorted(applications, key=_stamp, reverse=True):
        newest.setdefault(_system(application), str(application.get("id")))

    kept = set(newest.values())
    return [
        str(application["id"])
        for application in applications
        if str(application.get("id")) not in kept and _stamp(application) and _stamp(application) < cutoff
    ]


def prune(days: int | None = None, dry_run: bool = False, now: datetime | None = None) -> dict[str, Any]:
    """Delete expired scans; ``days`` of 0 or less keeps everything."""
    days = settings.SCAN_RETENTION_DAYS if days is None else days
    if days <= 0:
        return {"days": days, "cutoff": None, "dry_run": dry_run, "deleted": []}

    cutoff = ((now or datetime.now(UTC)) - timedelta(days=days)).isoformat()
    ids = expired(scans.list_applications(), cutoff)
    if not dry_run:
        ids = [application_id for application_id in ids if scans.delete_application(application_id)]
    return {"days": days, "cutoff": cutoff, "dry_run": dry_run, "deleted": ids}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=None, help="Retention window (default SECGUARD_SCAN_RETENTION_DAYS)")
    parser.add_argument("--dry-run", action="store_true", help="List the scans that would be deleted")
    arguments = parser.parse_args(argv)
    print(json.dumps(prune(arguments.days, arguments.dry_run), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
