"""Pull the client roster and per-client tool mapping from the Vendetta Platform
control plane.

The control plane is the system of record for which clients exist, which modules
they have on, and how each client maps into the tools. This module pulls
GET {platform_url}/api/platform/clients?module=managed-services and upserts its own
Client rows from it, keyed by the platform client id so the two stay aligned.

The pull is authoritative for the fields the platform owns (name, portal domains,
tool tenancy mapping). A client dropped from the platform roster, or with
managed-services turned off there, is deactivated here rather than deleted, so its
synced devices, alerts and message history are kept."""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import TOOLS, settings
from .db import Client

log = logging.getLogger(__name__)

_FIELD = {
    "superops": "superops_client_id",
    "sentinelone": "sentinelone_site_ids",
    "crowdstrike": "crowdstrike_cid",
    "huntress": "huntress_org_id",
    "acronis": "acronis_tenant_id",
}


class ProvisionError(Exception):
    pass


def configured() -> bool:
    return bool(settings.platform_url)


def _match(db: Session, entry: dict) -> Client | None:
    pid = entry["id"]
    c = db.query(Client).filter_by(platform_client_id=pid).one_or_none()
    if c:
        return c
    # Adopt a client created by hand here that matches by name, binding it to the
    # platform id from now on.
    c = db.query(Client).filter(Client.name.ilike(entry["name"])).one_or_none()
    if c and not c.platform_client_id:
        c.platform_client_id = pid
    return c


def _pull(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
    """Upsert clients from the platform. Returns a summary and never raises for a
    reachable platform; a transport failure raises ProvisionError."""
    if not configured():
        raise ProvisionError("PLATFORM_URL not set")
    headers = {"Authorization": f"Bearer {settings.platform_token}"} if settings.platform_token else {}
    url = f"{settings.platform_url.rstrip('/')}/api/platform/clients"
    try:
        with httpx.Client(timeout=20.0, transport=transport, headers=headers) as http:
            r = http.get(url, params={"module": "managed-services"})
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"platform unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise ProvisionError("platform rejected the token")
    if r.status_code != 200:
        raise ProvisionError(f"platform HTTP {r.status_code}")

    roster = r.json().get("clients") or []
    seen_pids = set()
    added = updated = 0
    for entry in roster:
        seen_pids.add(entry["id"])
        c = _match(db, entry)
        if c is None:
            c = Client(name=entry["name"], platform_client_id=entry["id"])
            db.add(c)
            added += 1
        else:
            updated += 1
        c.name = entry["name"]
        c.industry = entry.get("industry") or c.industry
        c.portal_domains = entry.get("portal_domains") or ""
        # A new client inherits the platform's portal state; an existing one keeps the
        # toggle set here, except that losing every domain closes the portal.
        if c.id is None or not entry.get("portal_domains"):
            c.portal_enabled = bool(entry.get("portal_domains"))
        c.executive_emails = entry.get("executive_emails") or ""
        c.active = True
        tools = entry.get("tools") or {}
        for t in TOOLS:
            setattr(c, _FIELD[t], (tools.get(t) or "").strip())
    db.flush()

    # Deactivate platform-managed clients no longer in the managed-services roster.
    deactivated = 0
    for c in db.query(Client).filter(Client.platform_client_id != "").all():
        if c.platform_client_id not in seen_pids and c.active:
            c.active = False
            deactivated += 1
    db.commit()
    summary = {"roster": len(roster), "added": added, "updated": updated, "deactivated": deactivated}
    log.info("platform pull: %s", summary)
    return summary


# ---------------------------------------------------------------- pull state and scheduling
# Outcome of the most recent pull, reported to the control plane through /api/module
# readiness so the go-live screen can tell "configured" from "actually syncing".
LAST: dict = {"at": None, "ok": None, "detail": "never run", "summary": None}


def _pull_recorded(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
    import datetime as _dt

    try:
        summary = _pull(db, transport)
    except ProvisionError as e:
        LAST.update(at=_dt.datetime.now(_dt.timezone.utc), ok=False, detail=str(e), summary=None)
        raise
    except Exception as e:  # noqa: BLE001
        LAST.update(at=_dt.datetime.now(_dt.timezone.utc), ok=False, detail=f"{type(e).__name__}: {e}", summary=None)
        raise
    LAST.update(at=_dt.datetime.now(_dt.timezone.utc), ok=True, detail="ok", summary=summary)
    return summary


pull = _pull_recorded


def state() -> dict:
    """Readiness view of the platform link: configured, token present, last pull."""
    return {
        "configured": configured(),
        "token_set": bool(getattr(settings, "platform_token", "")),
        "interval_seconds": int(getattr(settings, "provision_interval_seconds", 0) or 0),
        "last_ok": LAST["ok"],
        "last_at": LAST["at"].isoformat() if LAST["at"] else None,
        "last_detail": LAST["detail"],
    }


def start_scheduler(session_factory) -> None:
    """Pull the roster on an interval in a daemon thread. Does nothing when the
    control plane is not configured or the interval is 0, so standalone deployments
    and the test suite are unaffected."""
    import threading
    import time

    interval = int(getattr(settings, "provision_interval_seconds", 0) or 0)
    if not configured() or interval <= 0:
        return

    def _loop():
        time.sleep(5)  # let the web process finish booting first
        while True:
            db = session_factory()
            try:
                log.info("scheduled platform pull: %s", pull(db))
            except Exception as e:  # noqa: BLE001
                log.warning("scheduled platform pull failed: %s", e)
            finally:
                db.close()
            time.sleep(interval)

    threading.Thread(target=_loop, name="platform-pull", daemon=True).start()
