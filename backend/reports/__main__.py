"""Send the weekly digest from the server host: ``python -m backend.reports digest``."""

from __future__ import annotations

import argparse
import sys

from backend.notifications.channels import configured, send
from backend.reports.digest import digest_message, digest_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.reports")
    parser.add_argument("command", choices=["digest"])
    parser.add_argument("--dry-run", action="store_true", help="print the digest instead of sending it")
    arguments = parser.parse_args(argv)
    message = digest_message(digest_rows())
    if arguments.dry_run:
        print(message.title)
        print(message.plain())
        return 0
    if not any(configured().values()):
        print("No alert channel is configured (Slack, Teams or email).", file=sys.stderr)
        return 2
    results = send(message)
    for channel, result in results.items():
        print(f"{channel}: {result}")
    return 0 if all(result == "sent" for result in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
