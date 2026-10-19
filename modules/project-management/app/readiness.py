"""Operator-readiness flags this module reports to the platform control plane."""
from __future__ import annotations

from . import boot, integrations, provision, sso
from .config import settings

MODULE = "project-management"


def core() -> dict:
    s = sso.status()
    return {
        "module": MODULE,
        "enabled": bool(settings.module_enabled),
        "keys": {"signing_applicable": False, "signing_dedicated": False,
                 "encryption_dedicated": bool((settings.encryption_key or "").strip())},
        "sso": {"configured": s["configured"], "enabled": s["enabled"], "verified": s["verified"],
                "source": s["source"]},
        "hub_configured": False,
        "hub_token_set": False,
        "platform": provision.state(),
        "posture": {
            "secret_placeholder": bool(boot.problems()),
            "cookie_secure": bool(settings.cookie_secure),
            "admin_login_possible": bool((settings.admin_password_hash or "").strip()),
            "api_token_dedicated": bool((settings.api_token or "").strip()),
            "public_url": settings.public_url or "",
        },
    }


def integrations_block() -> dict:
    st = integrations.status()
    return {"kind": "connected-tools", "harvest": st["harvest"], "sharepoint_graph": st["graph"],
            "sharepoint_site": st["sharepoint_site"],
            # The Claude connector needs a public HTTPS URL for its OAuth metadata.
            "mcp_public_url": bool((settings.public_url or "").startswith("https://"))}


def block() -> dict:
    return {**core(), "integrations": integrations_block()}
