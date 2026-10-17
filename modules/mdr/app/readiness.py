"""Operator-readiness flags this module reports to the platform control plane.

The platform's /readiness screen aggregates these across every module into a
single go-live checklist: is the module enabled, is Microsoft 365 SSO verified,
are the signing and encryption keys dedicated, and is the signal source wired.
"""
from __future__ import annotations

from . import boot, detect, provision, sso
from .config import settings

MODULE = "mdr"


def core() -> dict:
    s = sso.status()
    return {
        "module": MODULE,
        "enabled": bool(settings.module_enabled),
        "keys": {
            "signing_applicable": True,
            "signing_dedicated": bool((settings.evidence_signing_key or "").strip()),
            "encryption_dedicated": bool((settings.encryption_key or "").strip()),
        },
        "sso": {"configured": s["configured"], "enabled": s["enabled"], "verified": s["verified"],
                "source": s["source"]},
        "hub_configured": bool(settings.platform_hub_url),
        "hub_token_set": bool(settings.platform_hub_token),
        "platform": provision.state(),
        "posture": {
            "secret_placeholder": bool(boot.problems()),
            "cookie_secure": bool(settings.cookie_secure),
            "admin_login_possible": bool((settings.admin_password_hash or "").strip()),
            "api_token_dedicated": bool((settings.api_token or "").strip()),
            "public_url": settings.public_url or "",
            "actions_readonly": None,
        },
    }


def integrations() -> dict:
    """The signal source: managed-services, read over its service API."""
    return {"kind": "signal-pull", "managed_services": detect.state()}


def block() -> dict:
    return {**core(), "integrations": integrations()}
