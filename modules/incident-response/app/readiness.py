"""Operator-readiness flags this module reports to the platform control plane.

The platform's /readiness screen aggregates these across every module into a
single go-live checklist: is the module enabled, is Microsoft 365 SSO verified
(not just saved), are the signing and encryption keys dedicated, and are the
module's own integrations wired.
"""
from __future__ import annotations

from . import boot, provision, sso
from .config import settings

MODULE = "incident-response"


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
        "hub_token_set": bool(getattr(settings, "platform_hub_token", "") or ""),
        # Control-plane link: configured, and whether the roster actually pulls.
        "platform": provision.state(),
        # Boot posture the control plane cannot see from outside.
        "posture": {
            "secret_placeholder": bool(boot.problems()),
            "cookie_secure": bool(getattr(settings, "cookie_secure", False)),
            "admin_login_possible": bool((getattr(settings, "admin_password_hash", "") or "").strip()),
            "api_token_dedicated": bool((getattr(settings, "api_token", "") or "").strip()),
            "public_url": getattr(settings, "public_url", "") or "",
            "actions_readonly": getattr(settings, "actions_readonly", None),
        },
    }


def integrations() -> dict:
    """IR consumes findings from the finding-serving modules via the hub; sources are
    discovered from the control-plane directory unless FINDINGS_SOURCES pins them."""
    pinned = settings.finding_source_list()
    return {"kind": "hub-consumer", "sources": "pinned" if pinned else "discovered",
            "pinned_count": len(pinned)}


def block() -> dict:
    return {**core(), "integrations": integrations()}
