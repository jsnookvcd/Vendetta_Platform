"""The onboarding note. When a person is onboarded on the Staff page, or
reactivated, the control plane sends them a plain-text welcome from SABINE with
the console link for every module they were granted and the one instruction that
matters: sign in with your Microsoft 365 account.

Delivery is SMTP, configured by SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
and SMTP_FROM. With no SMTP_HOST the note is logged and nothing is sent. Sending
never fails the onboarding: a failure is logged and recorded in the audit log,
and the person is still on the roster and can sign in.

The sign-off follows the PERSONA setting that SABINE reads ("sabine" or "plain"),
mirrored here so the deployment can hand the control plane the same value."""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from typing import Callable

from .config import settings

log = logging.getLogger(__name__)

SENDER_NAME = "SABINE at Vendetta Cyber"
_LEVEL = {"viewer": "read only", "analyst": "analyst", "admin": "admin"}

# A test, or another deployment, may replace the transport: a callable taking
# (to, subject, body) and returning a short detail string.
Sender = Callable[[str, str, str], str]
_sender: Sender | None = None


def use_sender(fn: Sender | None) -> None:
    global _sender
    _sender = fn


def configured() -> bool:
    return bool((settings.smtp_host or "").strip())


def from_address() -> str:
    """SMTP_FROM, shown as "SABINE at Vendetta Cyber <addr>". A bare address gets
    the display name; a full "Name <addr>" is kept as entered."""
    raw = (settings.smtp_from or "").strip()
    if not raw:
        return SENDER_NAME
    name, addr = parseaddr(raw)
    return formataddr((name or SENDER_NAME, addr)) if addr else raw


def welcome_message(person, consoles: list[tuple[str, str, str]], *, reactivated: bool = False) -> tuple[str, str]:
    """Return (subject, body). consoles is [(display name, access level, url)] for
    every module the person was granted, the platform first. Plain text."""
    first = (person.name or "").strip().split(" ")[0] or person.email
    sabine = settings.persona != "plain"
    subject = "Welcome back to the Vendetta consoles" if reactivated else "Your Vendetta console access"
    lines = [f"Hi {first},", ""]
    if reactivated:
        lines.append("Your access to the Vendetta consoles is back on. Here is where you can go:")
    elif sabine:
        lines.append("You are on the roster. I have already told every module, so here is where you can go:")
    else:
        lines.append("You have been onboarded to the Vendetta Platform. Your consoles:")
    lines.append("")
    for name, level, url in consoles:
        lines.append(f"  {name} ({_LEVEL.get(level, level)}): {url}")
    if not consoles:
        lines.append("  No console is published yet; your administrator will send the links.")
    lines += ["", "Sign in with your Microsoft 365 account. There is no separate password.", ""]
    if sabine:
        lines += ["If a page refuses you, that is me doing my job; ask a platform admin to adjust the grant.", "",
                  "SABINE", "Vendetta Cyber"]
    else:
        lines += ["Questions about access go to a platform administrator.", "", "Vendetta Cyber"]
    return subject, "\n".join(lines) + "\n"


def _smtp_send(to: str, subject: str, body: str) -> str:
    msg = EmailMessage()
    msg["From"] = from_address()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(settings.smtp_port or 587)
    with smtplib.SMTP(settings.smtp_host.strip(), port, timeout=20) as s:
        if settings.smtp_starttls:
            s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password)
        s.send_message(msg)
    return f"sent via {settings.smtp_host.strip()}:{port}"


def send(to: str, subject: str, body: str) -> tuple[bool, str]:
    """Deliver one note. Returns (sent, detail) and never raises."""
    try:
        if _sender is not None:
            return True, _sender(to, subject, body) or "sent"
        if not configured():
            log.info("notify: SMTP_HOST unset; welcome note for %s logged only:\n%s", to, body)
            return False, "SMTP_HOST unset; logged only"
        return True, _smtp_send(to, subject, body)
    except Exception as e:  # noqa: BLE001
        log.error("notify: welcome note to %s failed: %s", to, e)
        return False, f"failed: {type(e).__name__}: {str(e)[:200]}"
