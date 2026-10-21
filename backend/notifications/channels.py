"""Deliver a message to every channel configured in the server environment."""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from urllib.parse import urlsplit

import requests

from backend.config import settings

log = logging.getLogger(__name__)

TIMEOUT = 10


@dataclass
class Message:
    title: str
    lines: list[str] = field(default_factory=list)
    link: str = ""

    def plain(self) -> str:
        body = "\n".join(self.lines)
        return f"{body}\n\n{self.link}" if self.link else body


def configured() -> dict[str, bool]:
    return {
        "slack": bool(settings.SLACK_WEBHOOK_URL),
        "teams": bool(settings.TEAMS_WEBHOOK_URL),
        "email": bool(settings.SMTP_HOST and settings.ALERT_EMAILS and settings.SMTP_FROM),
    }


def _post(url: str, payload: dict) -> None:
    if urlsplit(url).scheme != "https":
        raise ValueError("webhook URL must use https")
    response = requests.post(url, json=payload, timeout=TIMEOUT, allow_redirects=False)
    response.raise_for_status()


def _slack(message: Message) -> None:
    text = f"*{message.title}*\n" + "\n".join(message.lines)
    if message.link:
        text += f"\n<{message.link}|Open in SecGuard>"
    _post(settings.SLACK_WEBHOOK_URL, {"text": text})


def _teams(message: Message) -> None:
    body = [{"type": "TextBlock", "text": message.title, "weight": "Bolder", "size": "Medium", "wrap": True}]
    body += [{"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in message.lines]
    card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": body}
    if message.link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in SecGuard", "url": message.link}]
    _post(
        settings.TEAMS_WEBHOOK_URL,
        {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]},
    )


def _email(message: Message) -> None:
    email = EmailMessage()
    email["Subject"] = message.title
    email["From"] = settings.SMTP_FROM
    email["To"] = ", ".join(settings.ALERT_EMAILS)
    email.set_content(message.plain())
    if settings.SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=TIMEOUT)
    else:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=TIMEOUT)
    with server:
        if settings.SMTP_PORT != 465:
            server.starttls()
        if settings.SMTP_USERNAME:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(email)


_SENDERS = {"slack": _slack, "teams": _teams, "email": _email}


def send(message: Message) -> dict[str, str]:
    """Send to each configured channel; report "sent" or the failure per channel."""
    results = {}
    for channel, enabled in configured().items():
        if not enabled:
            continue
        try:
            _SENDERS[channel](message)
        except (requests.RequestException, smtplib.SMTPException, OSError, ValueError) as error:
            # The webhook URL is a credential, so only the exception type is logged.
            log.warning("SecGuard %s delivery failed: %s", channel, type(error).__name__)
            results[channel] = f"failed ({type(error).__name__})"
        else:
            results[channel] = "sent"
    return results
