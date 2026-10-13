"""Operator-readiness flags this module reports to the platform control plane.

The platform's /readiness screen aggregates these across every module into a
single go-live checklist: is the module enabled, is Microsoft 365 SSO verified
(not just saved), are the signing and encryption keys dedicated, and are the
module's own integrations wired.
"""
from __future__ import annotations

from . import sso
from .config import settings

MODULE = "penetration-testing"


def core() -> dict:
    s = sso.status()
    signing_applicable = hasattr(settings, "evidence_signing_key")
    return {
        "module": MODULE,
        "enabled": bool(getattr(settings, "module_enabled", True)),
        "keys": {
            "signing_applicable": signing_applicable,
            "signing_dedicated": bool((getattr(settings, "evidence_signing_key", "") or "").strip()),
            "encryption_dedicated": bool((getattr(settings, "encryption_key", "") or "").strip()),
        },
        "sso": {
            "configured": s["configured"],
            "enabled": s["enabled"],
            "verified": s["verified"],
            "source": s["source"],
        },
        "hub_configured": bool(getattr(settings, "platform_hub_url", "") or ""),
    }


def integrations() -> dict:
    """Engagements and findings are authored in-console; no external feed to wire."""
    return {"kind": "manual-entry", "mode": "in-console"}


def block() -> dict:
    return {**core(), "integrations": integrations()}
