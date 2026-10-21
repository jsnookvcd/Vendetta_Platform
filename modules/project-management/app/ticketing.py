"""Ticketing for a kickoff: open (or link) the engagement's ticket in the service desk.

Vendetta is choosing a ticketing system to replace the Jira Service Management
desks, so no provider is wired yet. A provider is a function that takes the
engagement and the kickoff request and returns {"ref": ..., "url": ...}; register it
in PROVIDERS and set KICKOFF_TICKETING to its name. Until then the kickoff records
the ticket step as skipped, and a ticket reference typed into the wizard is kept as
a link on the engagement.
"""
from __future__ import annotations

import os
from typing import Callable

PROVIDERS: dict[str, Callable[[object, dict], dict]] = {}


def provider() -> str:
    return (os.environ.get("KICKOFF_TICKETING") or "none").strip().lower()


def open_ticket(eng, request: dict) -> dict | None:
    """The ticket for this engagement, or None when no provider is configured."""
    fn = PROVIDERS.get(provider())
    if fn is None:
        return None
    return fn(eng, request)
