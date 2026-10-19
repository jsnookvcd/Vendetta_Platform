"""Backfill: re-match items already collected against a client's watch terms.

New terms only match items collected after they exist, so a victim post from last
month naming a newly onboarded client would never hit. Whenever terms are added
(starter terms from provisioning, an analyst on the client page or the terms API)
queue() records a BackfillRequest; the worker drains it within a minute through
app/work_requests.py and calls run_backfill(). The web container never runs a
backfill on the request thread.

A pending request for the same client absorbs later ones, so a burst of term
additions costs one pass over the items."""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import iab, work_requests
from .db import BackfillRequest, Client, Item, WatchTerm, utcnow
from .matcher import match_item

log = logging.getLogger(__name__)

DEFAULT_DAYS = 365
BATCH = 500


def run_backfill(db: Session, client_id: str, days: int = DEFAULT_DAYS, term_ids: list[str] | None = None,
                 include_iab: bool = False, now: dt.datetime | None = None) -> dict:
    """Match the client's enabled terms (or only `term_ids`) against items collected
    in the last `days` days. Existing hits are not duplicated. With include_iab the
    client's initial access broker profile is matched as well."""
    now = now or utcnow()
    client = db.get(Client, client_id)
    if client is None:
        return {"ok": False, "error": "client not found"}
    if not client.active:
        return {"ok": True, "skipped": "client is paused", "items_scanned": 0, "hits_new": 0}
    q = select(WatchTerm).where(WatchTerm.client_id == client_id, WatchTerm.enabled.is_(True))
    if term_ids is not None:
        q = q.where(WatchTerm.id.in_(term_ids))
    terms = list(db.execute(q).scalars())
    since = now - dt.timedelta(days=days)
    ids = list(db.execute(select(Item.id).where(Item.collected_at >= since).order_by(Item.collected_at)).scalars())
    hits = 0
    if terms or include_iab:
        # Load in id batches: match_item commits when it creates hits, which would
        # close a server-side cursor held across the loop.
        for i in range(0, len(ids), BATCH):
            for it in db.execute(select(Item).where(Item.id.in_(ids[i:i + BATCH]))).scalars().all():
                if terms:
                    hits += len(match_item(db, it, terms=terms))
                if include_iab:
                    hits += len([h for h in iab.match_iab(db, it) if h.client_id == client_id])
                db.expunge(it)
    return {"ok": True, "client_id": client_id, "days": days, "terms": len(terms),
            "items_scanned": len(ids), "hits_new": hits}


def queue(db: Session, client_id: str, term_ids: list[str] | None = None, requested_by: str = "system",
          reason: str = "", days: int = DEFAULT_DAYS, include_iab: bool = False) -> BackfillRequest:
    """Queue a backfill for the worker. term_ids None means every enabled term.
    Merges into a pending request for the same client when there is one."""
    # Row lock: the worker's claim takes the same lock, so a request it is about to
    # run is never widened after it has read the payload.
    rows = db.execute(select(BackfillRequest).where(
        BackfillRequest.status == work_requests.PENDING,
        BackfillRequest.payload["client_id"].as_string() == client_id,
    ).order_by(BackfillRequest.requested_at).limit(1).with_for_update(skip_locked=True)).scalars().all()
    for req in rows:
        p = dict(req.payload or {})
        if p.get("term_ids") is None or term_ids is None:
            p["term_ids"] = None
        else:
            p["term_ids"] = sorted(set(p["term_ids"]) | set(term_ids))
        p["days"] = max(int(p.get("days") or 0), days)
        p["include_iab"] = bool(p.get("include_iab")) or include_iab
        reasons = [r for r in (p.get("reason") or "").split(", ") if r]
        if reason and reason not in reasons:
            reasons.append(reason)
        p["reason"] = ", ".join(reasons)
        req.payload = p  # reassign so the JSON column is marked dirty
        db.commit()
        return req
    return work_requests.enqueue(db, BackfillRequest, requested_by, {
        "client_id": client_id, "days": days, "term_ids": list(term_ids) if term_ids is not None else None,
        "include_iab": include_iab, "reason": reason,
    })


def handle(db: Session, req: BackfillRequest) -> dict:
    p = req.payload or {}
    return run_backfill(db, p.get("client_id", ""), int(p.get("days") or DEFAULT_DAYS),
                        p.get("term_ids"), bool(p.get("include_iab")))


def drain(db: Session, limit: int = 5) -> int:
    return work_requests.drain(db, BackfillRequest, lambda req: handle(db, req), limit=limit)


def client_state(db: Session, client_id: str) -> dict:
    """What the client page shows: the last finished backfill and any queued one."""
    mine = db.execute(select(BackfillRequest).where(BackfillRequest.payload["client_id"].as_string() == client_id)
                      .order_by(BackfillRequest.requested_at.desc()).limit(20)).scalars().all()
    last = next((r for r in mine if r.status in (work_requests.DONE, work_requests.FAILED)), None)
    queued = next((r for r in mine if r.status in (work_requests.PENDING, work_requests.RUNNING)), None)
    return {"last": last, "queued": queued}
