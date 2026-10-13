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


def pull(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
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
        c.portal_enabled = bool(entry.get("portal_domains"))
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
