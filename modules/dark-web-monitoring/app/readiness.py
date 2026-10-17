"""Operator-readiness flags this module reports to the platform control plane.

The platform's /readiness screen aggregates these across every module into a
single go-live checklist: is the module enabled, is Microsoft 365 SSO verified
(not just saved), are the signing and encryption keys dedicated, and are the
module's own integrations wired.
"""
from __future__ import annotations

from . import boot, provision, sso
from .config import settings

MODULE = "dark-web-monitoring"


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
    """Collection health for the control plane. `kind` and `configured` (the count
    of Source rows) are the original keys and stay. `tor`, the worker heartbeat age
    and per-connector state let the readiness screen show this module red when Tor
    or the worker is down and warn when a connector is failing or stale."""
    out: dict = {"kind": "collection-sources", "configured": 0, "tor": {"ok": False, "checked_at": None,
                 "error": "no Tor check recorded"}, "worker_heartbeat_age_seconds": None, "connectors": {}}
    try:
        from . import connectors
        from .db import SessionLocal, Source
        db = SessionLocal()
        try:
            out["configured"] = db.query(Source).count()
            summary = connectors.health_summary(db)
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        out["error"] = f"health unavailable: {type(e).__name__}"
        return out
    tor = summary["tor"]
    if tor:
        out["tor"] = {"ok": bool(tor.get("is_tor")), "reachable": bool(tor.get("reachable")),
                      "checked_at": tor.get("checked_at"), "error": tor.get("error", "")}
    out["worker_heartbeat_age_seconds"] = summary["heartbeat_age_seconds"]
    out["heartbeat_stale_after_seconds"] = health_stale_after()
    out["connectors"] = {
        r["key"]: {
            "configured": r["configured"],
            "reason": r["reason"],
            "last_ok": r["last_ok"].isoformat() if r["last_ok"] else None,
            "last_run_ok": r["last_run_ok"],
            "stale": r["stale"],
            "error": r["error"],
        }
        for r in summary["connectors"]
    }
    return out


def health_stale_after() -> int:
    from .health import HEARTBEAT_STALE_SECONDS
    return HEARTBEAT_STALE_SECONDS


def block() -> dict:
    return {**core(), "integrations": integrations()}
