"""Engagement milestones, and publishing the client-visible ones to the client.

IR engagements publish to their IR hub case (platform_ref is the case number, like
VCD-IR-2026-781); the hub shows them on the case in its client portal and writes a
client-visible timeline entry when one completes. ProServ engagements publish to
their Office of Special Projects engagement (platform_ref is the OSP engagement id),
whose portal shows them beside the deliverables.

Publishing sends the full client-visible list each time, so it is idempotent and a
missed publish heals on the next change. Internal milestones never leave this module.
"""
from __future__ import annotations

import datetime as dt
import logging

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import IR_WORKSTREAMS, MILESTONE_STATUSES, settings
from .db import Engagement, Milestone, utcnow

log = logging.getLogger(__name__)
TRANSPORT: httpx.BaseTransport | None = None


def _err(msg: str, status: int = 400):
    from .service import ServiceError
    return ServiceError(msg, status)


def find(db: Session, eng: Engagement, ref: str) -> Milestone:
    ref = (ref or "").strip()
    m = db.get(Milestone, ref)
    if m and m.engagement_id == eng.id:
        return m
    rows = db.execute(select(Milestone).where(Milestone.engagement_id == eng.id)).scalars().all()
    exact = [r for r in rows if r.title.lower() == ref.lower()]
    part = exact or [r for r in rows if ref.lower() in r.title.lower()]
    if len(part) == 1:
        return part[0]
    names = "; ".join(r.title for r in rows) or "none"
    raise _err(f"'{ref}' does not match one milestone on {eng.code}. Milestones: {names}", 404)


def _ws(eng: Engagement, ws: str | None) -> str:
    ws = (ws or "").strip()
    if not ws:
        return ""
    if eng.practice != "ir":
        return ws
    for w in IR_WORKSTREAMS:
        if w.lower() == ws.lower() or w.lower().startswith(ws.lower()):
            return w
    raise _err(f"Workstream must be one of: {', '.join(IR_WORKSTREAMS)}")


def add(db: Session, actor: str, eng: Engagement, *, title: str, due_on=None, workstream: str | None = None,
        client_visible: bool = True) -> Milestone:
    from .service import parse_date

    if not (title or "").strip():
        raise _err("A milestone needs a title")
    pos = db.scalar(select(func.count(Milestone.id)).where(Milestone.engagement_id == eng.id)) or 0
    m = Milestone(engagement_id=eng.id, title=title.strip()[:300], due_on=parse_date(due_on),
                  workstream=_ws(eng, workstream), client_visible=bool(client_visible), position=pos)
    db.add(m)
    db.flush()
    return m


def update(db: Session, actor: str, m: Milestone, *, title=None, status=None, due_on=None, workstream=None,
           client_visible=None) -> Milestone:
    from .service import parse_date

    if title is not None and title.strip():
        m.title = title.strip()[:300]
    if status is not None:
        st = status.strip().lower().replace(" ", "_")
        if st not in MILESTONE_STATUSES:
            raise _err(f"Milestone status must be one of: {', '.join(MILESTONE_STATUSES)}")
        m.status = st
        m.completed_at = (m.completed_at or utcnow()) if st == "done" else None
    if due_on is not None:
        m.due_on = parse_date(due_on) if due_on != "none" else None
    if workstream is not None:
        m.workstream = _ws(m.engagement, workstream)
    if client_visible is not None:
        m.client_visible = bool(client_visible)
    db.flush()
    return m


def remove(db: Session, actor: str, m: Milestone) -> None:
    db.delete(m)
    db.flush()


def milestone_dict(m: Milestone) -> dict:
    today = dt.date.today()
    return {"id": m.id, "title": m.title, "status": m.status, "workstream": m.workstream or None,
            "due_on": m.due_on.isoformat() if m.due_on else None,
            "completed_on": m.completed_at.date().isoformat() if m.completed_at else None,
            "overdue": bool(m.due_on and m.due_on < today and m.status != "done"),
            "client_visible": m.client_visible}


def list_for(db: Session, eng: Engagement) -> list[Milestone]:
    return list(db.execute(select(Milestone).where(Milestone.engagement_id == eng.id)
                           .order_by(Milestone.position, Milestone.created_at)).scalars())


# ---------------------------------------------------------------- publishing
def payload(db: Session, eng: Engagement) -> dict:
    return {"source_module": "project-management", "engagement_code": eng.code,
            "milestones": [{"key": m.id, "title": m.title, "workstream": m.workstream, "status": m.status,
                            "due_on": m.due_on.isoformat() if m.due_on else None,
                            "completed_on": m.completed_at.date().isoformat() if m.completed_at else None}
                           for m in list_for(db, eng) if m.client_visible]}


def target(eng: Engagement) -> tuple[str, str, str] | None:
    """(url, token, label) the engagement's milestones publish to, or None."""
    ref = (eng.platform_ref or "").strip()
    if not ref:
        return None
    if eng.practice == "ir" and settings.platform_hub_url:
        return (f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases/{ref}/milestones",
                settings.platform_hub_token, f"IR hub case {ref}")
    if eng.practice == "proserv" and settings.osp_url:
        return (f"{settings.osp_url.rstrip('/')}/api/engagements/{ref}/milestones",
                settings.osp_token, f"OSP engagement {ref}")
    return None


def publish(db: Session, eng: Engagement) -> dict:
    """Push the client-visible milestones. Records the outcome on the engagement and
    never raises; the caller commits."""
    t = target(eng)
    if t is None:
        eng.publish_status = "off"
        eng.publish_detail = ("Set the platform reference (the IR case number or OSP engagement id) to show "
                              "milestones to the client" if not eng.platform_ref
                              else "Client portal publishing is not configured for this practice")
        return {"published": False, "reason": eng.publish_detail}
    url, token, label = t
    headers = {"Authorization": f"Bearer {token}", "X-Vendetta-Actor": "project-management"} if token else {}
    try:
        with httpx.Client(timeout=15.0, transport=TRANSPORT, headers=headers) as http:
            r = http.post(url, json=payload(db, eng))
    except httpx.HTTPError as e:
        eng.publish_status, eng.publish_detail = "failed", f"{label} unreachable: {type(e).__name__}"
        return {"published": False, "reason": eng.publish_detail}
    if r.status_code == 404:
        eng.publish_status, eng.publish_detail = "failed", f"{label} was not found; check the platform reference"
    elif r.status_code >= 400:
        eng.publish_status, eng.publish_detail = "failed", f"{label} refused the update (HTTP {r.status_code})"
    else:
        eng.publish_status, eng.publish_detail, eng.published_at = "ok", f"Shown on {label}", utcnow()
        return {"published": True, "to": label}
    log.warning("milestone publish for %s: %s", eng.code, eng.publish_detail)
    return {"published": False, "reason": eng.publish_detail}
