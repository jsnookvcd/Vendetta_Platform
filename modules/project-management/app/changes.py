"""Scope and change control.

An engagement keeps the baseline it was sold at (hours and end date). Anything that
would move it is a change request: hours added (or removed), days added to the end
date, why, and who at the client agreed. Approving one moves the engagement's
working budget and end date; rejecting or withdrawing it moves nothing. The
difference between baseline and working budget is the scope growth the portfolio
metrics report, and burn past the baseline with no approved change behind it is
raised as an alert so it is caught before it is written off.

Approval is a second person's decision: the requester cannot approve their own
request unless they are an admin.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import CHANGE_REASONS
from .db import ChangeRequest, Engagement, utcnow


def _err(msg: str, status: int = 400):
    from .service import ServiceError
    return ServiceError(msg, status)


def find(db: Session, eng: Engagement, ref) -> ChangeRequest:
    s = str(ref or "").strip().upper().replace("CR-", "").replace("CR", "").strip()
    cr = None
    if s.isdigit():
        cr = db.execute(select(ChangeRequest).where(ChangeRequest.engagement_id == eng.id,
                                                    ChangeRequest.number == int(s))).scalar_one_or_none()
    cr = cr or db.get(ChangeRequest, str(ref or ""))
    if cr is None or cr.engagement_id != eng.id:
        raise _err(f"{eng.code} has no change request {ref}", 404)
    return cr


def request(db: Session, actor: str, eng: Engagement, *, title: str, description: str = "",
            hours_delta=0, days_delta=0, reason: str = "client_request", client_approval: str = "") -> ChangeRequest:
    if not (title or "").strip():
        raise _err("A change request needs a title")
    reason = (reason or "client_request").strip().lower().replace(" ", "_")
    if reason not in CHANGE_REASONS:
        raise _err(f"Reason must be one of: {', '.join(CHANGE_REASONS)}")
    try:
        h, d = float(hours_delta or 0), int(days_delta or 0)
    except (TypeError, ValueError) as e:
        raise _err("hours_delta must be a number and days_delta a whole number of days") from e
    if h == 0 and d == 0:
        raise _err("A change request must move the hours, the end date, or both")
    n = (db.scalar(select(func.max(ChangeRequest.number)).where(ChangeRequest.engagement_id == eng.id)) or 0) + 1
    cr = ChangeRequest(engagement_id=eng.id, number=n, title=title.strip()[:300], description=description or "",
                       reason=reason, hours_delta=h, days_delta=d, client_approval=client_approval or "",
                       requested_by=actor)
    db.add(cr)
    db.flush()
    return cr


def decide(db: Session, actor: str, actor_role: str, cr: ChangeRequest, decision: str, note: str = "",
           client_approval: str | None = None) -> ChangeRequest:
    decision = (decision or "").strip().lower()
    if cr.status != "requested":
        raise _err(f"CR-{cr.number} is already {cr.status}", 409)
    if decision == "withdraw":
        if actor != cr.requested_by and actor_role != "admin":
            raise _err("Only the requester or an admin can withdraw a change request", 403)
        cr.status = "withdrawn"
    elif decision in ("approve", "reject"):
        if actor == cr.requested_by and actor_role != "admin":
            raise _err("A second person approves or rejects a change request; you raised this one", 403)
        if client_approval is not None:
            cr.client_approval = client_approval
        if decision == "approve":
            eng = cr.engagement
            if eng.baseline_budget_hours is None:
                eng.baseline_budget_hours = eng.budget_hours
            if eng.baseline_ends_on is None:
                eng.baseline_ends_on = eng.ends_on
            if cr.hours_delta:
                eng.budget_hours = round((eng.budget_hours or 0) + cr.hours_delta, 2)
            if cr.days_delta:
                eng.ends_on = (eng.ends_on or dt.date.today()) + dt.timedelta(days=cr.days_delta)
            cr.status = "approved"
        else:
            cr.status = "rejected"
    else:
        raise _err("Decision must be approve, reject or withdraw")
    cr.decided_by, cr.decided_at, cr.decision_note = actor, utcnow(), note or ""
    db.flush()
    return cr


def cr_dict(cr: ChangeRequest) -> dict:
    return {"id": cr.id, "number": f"CR-{cr.number}", "engagement": cr.engagement.code, "title": cr.title,
            "description": cr.description, "reason": cr.reason, "hours_delta": cr.hours_delta,
            "days_delta": cr.days_delta, "status": cr.status, "client_approval": cr.client_approval or None,
            "requested_by": cr.requested_by, "requested_at": cr.requested_at.isoformat(),
            "decided_by": cr.decided_by or None,
            "decided_at": cr.decided_at.isoformat() if cr.decided_at else None, "decision_note": cr.decision_note}


def list_for(db: Session, *, engagement: Engagement | None = None, status: str | None = None) -> list[ChangeRequest]:
    q = select(ChangeRequest)
    if engagement:
        q = q.where(ChangeRequest.engagement_id == engagement.id)
    if status and status != "all":
        q = q.where(ChangeRequest.status == status)
    return list(db.execute(q.order_by(ChangeRequest.requested_at.desc())).scalars())


def scope_summary(db: Session, eng: Engagement) -> dict:
    rows = list_for(db, engagement=eng)
    approved = [c for c in rows if c.status == "approved"]
    return {"baseline_hours": eng.baseline_budget_hours, "current_hours": eng.budget_hours,
            "approved_hours_added": round(sum(c.hours_delta for c in approved), 2),
            "approved_days_added": sum(c.days_delta for c in approved),
            "baseline_ends_on": eng.baseline_ends_on.isoformat() if eng.baseline_ends_on else None,
            "current_ends_on": eng.ends_on.isoformat() if eng.ends_on else None,
            "pending": [cr_dict(c) for c in rows if c.status == "requested"]}
