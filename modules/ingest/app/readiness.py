"""Operator-readiness flags this module reports to the platform control plane.

Besides the flags every module reports, Telemetry Ingest reports what the go-live
screen needs to tell a working pipeline from a configured one: connectors that are
failing or stale, whether sealing and anchoring are current, and the detection pass.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select

from . import boot, provision, sinks, sso, stream, worker
from .config import settings
from .db import Batch, Connector, Event, SessionLocal, utcnow

MODULE = "ingest"
STALE_AFTER = dt.timedelta(hours=24)


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


def connector_health(db, now: dt.datetime | None = None) -> list[dict]:
    now = now or utcnow()
    out = []
    for c in db.execute(select(Connector).where(Connector.enabled.is_(True))).scalars():
        stale = c.newest_event_at is None or (now - c.newest_event_at) > STALE_AFTER
        out.append({"id": c.id, "source": c.source, "client_id": c.client_id,
                    "last_ok": bool(c.last_ok_at) and not c.last_error,
                    "last_ok_at": c.last_ok_at.isoformat() if c.last_ok_at else None,
                    "error": c.last_error or "", "stale": stale,
                    "newest_event_at": c.newest_event_at.isoformat() if c.newest_event_at else None})
    return out


def integrations() -> dict:
    db = SessionLocal()
    try:
        now = utcnow()
        health = connector_health(db, now)
        unsealed_oldest = db.scalar(select(func.min(Event.received_at)).where(Event.batch_id.is_(None)))
        last_seal = db.scalar(select(func.max(Batch.sealed_at)))
        return {
            "kind": "telemetry",
            "connectors": {"enabled": len(health), "failing": sum(1 for h in health if h["error"]),
                           "stale": sum(1 for h in health if h["stale"]), "items": health[:200]},
            "sealing": {"last_sealed_at": last_seal.isoformat() if last_seal else None,
                        "oldest_unsealed_seconds": int((now - unsealed_oldest).total_seconds())
                        if unsealed_oldest else 0},
            "detection": stream.state(),
            "worker": worker.state(),
            "sinks": sinks.configured(),
        }
    except Exception as e:  # noqa: BLE001
        return {"kind": "telemetry", "error": type(e).__name__}
    finally:
        db.close()


def block() -> dict:
    return {**core(), "integrations": integrations()}
