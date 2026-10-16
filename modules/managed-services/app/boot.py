"""Fail-closed boot checks. A module refuses to start on placeholder secrets so a
misrendered .env can never put a console on the network with a guessable session
signer. ALLOW_INSECURE_DEFAULTS=true bypasses this for a developer laptop only."""
from __future__ import annotations

import logging

from .config import settings

log = logging.getLogger(__name__)

PLACEHOLDER_SECRETS = {"", "change-me", "replace-with-64-random-chars", "changeme", "secret"}


def problems() -> list[str]:
    out = []
    if (settings.secret_key or "").strip().lower() in PLACEHOLDER_SECRETS:
        out.append("SECRET_KEY is a placeholder")
    return out


def check() -> None:
    """Raise at startup on a blocking problem unless insecure defaults are allowed."""
    found = problems()
    if not found:
        return
    if settings.allow_insecure_defaults:
        for p in found:
            log.warning("insecure default allowed by ALLOW_INSECURE_DEFAULTS: %s", p)
        return
    raise RuntimeError("refusing to start: " + "; ".join(found)
                       + ". Set real values in .env, or ALLOW_INSECURE_DEFAULTS=true for local development only.")
