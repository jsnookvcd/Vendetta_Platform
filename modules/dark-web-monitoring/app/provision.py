"""Pull the client roster from the Vendetta Platform control plane.

Pulls GET {platform_url}/api/platform/clients?module=dark-web-monitoring and upserts
Client rows keyed by the platform client id, so a client lines up across the
platform and every module.

The pull is authoritative only for the platform-owned fields (name, portal
domains). It never touches dark-web-owned data: watch terms, the IAB business
profile (industry, country, revenue and so on), case_ref and collected hits are all
left alone, so onboarding and tuning done here survive a pull. A client dropped from
the roster is deactivated, not deleted, so its collection history is kept."""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .db import Client

log = logging.getLogger(__name__)


class ProvisionError(Exception):
    pass


def configured() -> bool:
    return bool(settings.platform_url)


def _match(db: Session, entry: dict) -> Client | None:
    pid = entry["id"]
    c = db.query(Client).filter_by(platform_client_id=pid).one_or_none()
    if c:
        return c
    c = db.query(Client).filter(Client.name.ilike(entry["name"])).one_or_none()
    if c and not c.platform_client_id:
        c.platform_client_id = pid
    return c


def pull(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
    if not configured():
        raise ProvisionError("PLATFORM_URL not set")
    headers = {"Authorization": f"Bearer {settings.platform_token}"} if settings.platform_token else {}
    url = f"{settings.platform_url.rstrip('/')}/api/platform/clients"
    try:
        with httpx.Client(timeout=20.0, transport=transport, headers=headers) as http:
            r = http.get(url, params={"module": "dark-web-monitoring"})
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"platform unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise ProvisionError("platform rejected the token")
    if r.status_code != 200:
        raise ProvisionError(f"platform HTTP {r.status_code}")

    roster = r.json().get("clients") or []
    seen = set()
    added = updated = 0
    for entry in roster:
        seen.add(entry["id"])
        c = _match(db, entry)
        if c is None:
            # New dark web clients come in as managed; onboarding adds watch terms
            # and the IAB profile afterward.
            c = Client(name=entry["name"], platform_client_id=entry["id"], kind="managed")
            db.add(c)
            added += 1
        else:
            updated += 1
        c.name = entry["name"]
        c.portal_domains = entry.get("portal_domains") or ""
        c.portal_enabled = bool(entry.get("portal_domains"))
        c.executive_emails = entry.get("executive_emails") or ""
        # Fill industry only when it is not already set here (the IAB profile owns it).
        if entry.get("industry") and not c.industry:
            c.industry = entry["industry"]
        c.active = True
    db.flush()

    deactivated = 0
    for c in db.query(Client).filter(Client.platform_client_id != "").all():
        if c.platform_client_id not in seen and c.active:
            c.active = False
            deactivated += 1
    db.commit()
    summary = {"roster": len(roster), "added": added, "updated": updated, "deactivated": deactivated}
    log.info("platform pull: %s", summary)
    return summary
