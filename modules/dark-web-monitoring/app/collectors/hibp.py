"""Have I Been Pwned. Requires an API key and, for domain queries, a verified
domain on the HIBP account (Pwned 2 or higher plan covers domain search and
stealer logs). Terms of kind domain and email_domain are queried.

Endpoints:
  breacheddomain/{domain}            aliases -> breach names, by domain
  stealerlogsbyemaildomain/{domain}  aliases -> websites, from infostealer logs
  stealerlogsbywebsitedomain/{domain} emails that logged into the client's own sites

Infostealer hits are treated as high severity by default because they usually
mean a live credential on an infected endpoint."""
from __future__ import annotations

import logging
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Client, Source, WatchTerm
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

BASE = "https://haveibeenpwned.com/api/v3"


def _get(path: str):
    r = httpx.get(
        f"{BASE}/{path}",
        headers={"hibp-api-key": settings.hibp_api_key, "user-agent": "VendettaDarkWebMonitor"},
        timeout=30,
    )
    if r.status_code == 404:
        return None
    if r.status_code in (401, 403):
        # Endpoint not included in the subscription tier (stealer logs need a Pro plan).
        log.warning("hibp %s: HTTP %s, endpoint not available on this subscription", path.split("/")[0], r.status_code)
        return None
    if r.status_code == 429:
        time.sleep(int(r.headers.get("retry-after", "5")))
        return _get(path)
    r.raise_for_status()
    return r.json()


def _source(db: Session) -> Source:
    src = db.execute(select(Source).where(Source.kind == "hibp")).scalar_one_or_none()
    if not src:
        src = Source(name="Have I Been Pwned", kind="hibp", url=BASE)
        db.add(src)
        db.commit()
    return src


def _domains(db: Session) -> list[tuple[str, str]]:
    rows = db.execute(
        select(WatchTerm.term, Client.id).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True), WatchTerm.kind.in_(("domain", "email_domain")))
    ).all()
    seen = set()
    out = []
    for term, cid in rows:
        d = term.strip().lower()
        if d not in seen:
            seen.add(d)
            out.append((d, cid))
    return out


def run(db: Session) -> None:
    if not settings.hibp_api_key:
        log.info("hibp: no API key, skipping")
        return
    src = _source(db)
    try:
        for domain, _cid in _domains(db):
            breached = _get(f"breacheddomain/{domain}") or {}
            for alias, breaches in breached.items():
                email = f"{alias}@{domain}"
                for b in breaches:
                    ingest(
                        db,
                        kind="breach",
                        title=f"{email} in breach {b}",
                        body=f"Email: {email}\nBreach: {b}\nDomain: {domain}",
                        url=f"https://haveibeenpwned.com/PwnedWebsites#{b}",
                        external_id=f"hibp:{email}:{b}",
                        group_name=b,
                        source=src,
                        hash_parts=("breach", email.lower(), b),
                        preserve_on_hit=False,
                    )
            time.sleep(1.6)  # HIBP rate limit on the lower tiers
            stealer = _get(f"stealerlogsbyemaildomain/{domain}") or {}
            for alias, sites in stealer.items():
                email = f"{alias}@{domain}"
                ingest(
                    db,
                    kind="stealer",
                    title=f"Infostealer log: {email}",
                    body=f"Email: {email}\nCaptured logins to: {', '.join(sites)}\nDomain: {domain}",
                    url="https://haveibeenpwned.com/",
                    external_id=f"hibp-stealer:{email}",
                    group_name="infostealer",
                    source=src,
                    meta={"sites": sites},
                    hash_parts=("stealer", email.lower(), ",".join(sorted(sites))),
                    preserve_on_hit=False,
                )
            time.sleep(1.6)
            site_logs = _get(f"stealerlogsbywebsitedomain/{domain}") or []
            for email in site_logs:
                ingest(
                    db,
                    kind="stealer",
                    title=f"Infostealer log for login to {domain}: {email}",
                    body=f"Email: {email}\nLogged in to: {domain}\nSource: infostealer log",
                    url="https://haveibeenpwned.com/",
                    external_id=f"hibp-site:{domain}:{email}",
                    group_name="infostealer",
                    source=src,
                    hash_parts=("stealer-site", domain, str(email).lower()),
                    preserve_on_hit=False,
                )
            time.sleep(1.6)
        mark_source(db, src, True)
    except Exception as e:  # noqa: BLE001
        log.exception("hibp run failed")
        mark_source(db, src, False, str(e))
