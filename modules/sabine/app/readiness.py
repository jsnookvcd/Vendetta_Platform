"""What SABINE reports to the control plane's go-live screen, in the same shape
every module uses, plus its own: how many modules it can reach, when it last
ran, whether the chain verifies, and which optional business sources (Harvest,
HubSpot) are configured."""
from __future__ import annotations

from . import boot, brain, business, provision, reach, sso
from .config import settings

MODULE = "sabine"


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
        "sso": {"configured": s["configured"], "enabled": s["enabled"], "verified": s["verified"], "source": s["source"]},
        "hub_configured": "incident-response" in reach.directory(),
        "hub_token_set": bool(reach.directory().get("incident-response", {}).get("token")),
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
    d = reach.directory()
    return {
        "kind": "agent",
        "reach": sorted(d.keys()),
        "narrative": "llm" if (settings.anthropic_api_key or "").strip() else "rules",
        "cycle_interval_seconds": settings.cycle_interval_seconds,
        "last_cycle_ok": brain.LAST["ok"],
        "last_cycle_at": brain.LAST["at"].isoformat() if brain.LAST["at"] else None,
        "last_cycle_detail": brain.LAST["detail"],
        # Optional business sources: "configured" or "not configured" (skipped).
        "business": business.status(),
    }


def block() -> dict:
    return {**core(), "integrations": integrations()}
