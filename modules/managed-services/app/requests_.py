"""Requested response actions: ask in one place, a second person approves, then it
runs through the same dispatcher and the same signed action log as a console click.

The rules, all enforced here whatever the caller checked first:
- read-only mode refuses a request before anyone is asked to approve it;
- the requester must be allowed to run response actions (can_act);
- a non-destructive action (lift containment, reconnect) runs at once;
- a destructive one (contain, isolate) waits for a different person with approval
  rights; the requester can never approve their own, even where the console allows
  self-approval;
- a request no one answers within REQUEST_TTL_MINUTES expires and never runs;
- at execution the requester's right to act is checked again, so someone whose
  access was removed while the request waited cannot have it run.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from . import actions as act
from .config import settings
from .db import ActionRequest, Alert, Device, User, utcnow

REQUEST_TTL_MINUTES = 30


class Refused(Exception):
    def __init__(self, detail: str, status: int = 409):
        super().__init__(detail)
        self.detail, self.status = detail, status


def caps(db: Session, email: str) -> tuple[bool, bool]:
    """(can_act, can_approve) from this module's mirror of the staff roster."""
    if email == settings.admin_user:
        return True, True
    u = db.query(User).filter_by(email=email).one_or_none()
    if not u or not u.active or u.role in ("viewer", "client"):
        return False, False
    if u.role == "admin":
        return True, True
    return bool(u.can_act), bool(u.can_approve)


def split_actor(actor: str) -> tuple[str, str]:
    """"dan@x.io via slack" -> ("dan@x.io", "slack")."""
    if " via " in actor:
        email, via = actor.split(" via ", 1)
        return email.strip().lower(), via.strip()
    return actor.strip().lower(), ""


def device_json(db: Session, d: Device) -> dict:
    alerts = db.execute(select(Alert).where(Alert.device_id == d.id, Alert.status != "resolved")
                        .order_by(Alert.received_at.desc()).limit(10)).scalars().all()
    return {
        "id": d.id, "tool": d.tool, "hostname": d.hostname, "platform": d.platform, "status": d.status,
        "agent_version": d.agent_version, "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "link": d.link, "client": d.client.name if d.client else "",
        "platform_client_id": d.client.platform_client_id if d.client else "",
        "open_alerts": [{"id": a.id, "severity": a.severity, "title": (a.title or "")[:200], "status": a.status,
                         "occurred_at": a.occurred_at.isoformat() if a.occurred_at else None} for a in alerts],
        "actions": [{"id": a.id, "label": a.label, "destructive": a.danger} for a in act.DEVICE_ACTIONS.get(d.tool, [])],
    }


def request_json(r: ActionRequest) -> dict:
    spec = act.spec(r.action_id)
    return {
        "id": r.id, "status": r.status, "action_id": r.action_id, "action": spec.label if spec else r.action_id,
        "destructive": bool(spec and spec.danger), "tool": r.tool,
        "hostname": r.device.hostname if r.device else "", "client": r.client.name if r.client else "",
        "requested_by": r.requested_by, "via": r.via, "reason": r.reason, "source_ref": r.source_ref,
        "decided_by": r.decided_by, "detail": r.detail,
        "created_at": r.created_at.isoformat(), "expires_at": r.expires_at.isoformat() if r.expires_at else None,
    }


def _expire(r: ActionRequest) -> bool:
    if r.status == "pending" and r.expires_at and utcnow() > r.expires_at:
        r.status, r.detail = "expired", f"no approval within {REQUEST_TTL_MINUTES} minutes"
        return True
    return False


def get(db: Session, rid: str) -> ActionRequest:
    r = db.execute(select(ActionRequest).options(selectinload(ActionRequest.device).selectinload(Device.client),
                                                 selectinload(ActionRequest.client))
                   .where(ActionRequest.id == rid)).scalar_one_or_none()
    if r is None:
        raise Refused("no such request", 404)
    if _expire(r):
        db.commit()
    return r


def _run(db: Session, r: ActionRequest, approver: str) -> None:
    can_act, _ = caps(db, r.requested_by)
    actor = f"{r.requested_by} via {r.via}" if r.via else r.requested_by
    comment = (r.reason or f"Requested via {r.via or 'API'}")[:500]
    ok, detail = act.run_device_action(db, r.device, r.action_id, actor, comment=comment, confirm=True,
                                       can_act=can_act, approver=approver)
    r.status = "done" if ok else ("blocked" if detail and ("read-only" in detail or "permission" in detail) else "failed")
    r.detail = detail[:2000]


def create(db: Session, actor: str, device_id: str, action_id: str, *, platform_client_id: str = "",
           reason: str = "", source_ref: str = "") -> ActionRequest:
    email, via = split_actor(actor)
    d = db.execute(select(Device).options(selectinload(Device.client)).where(Device.id == device_id)).scalar_one_or_none()
    if d is None or (platform_client_id and (not d.client or d.client.platform_client_id != platform_client_id)):
        raise Refused("no such device for that client", 404)
    spec = act.spec(action_id)
    if spec is None or spec not in act.DEVICE_ACTIONS.get(d.tool, []):
        raise Refused(f"that action does not apply to a {d.tool} device", 400)
    if settings.actions_readonly:
        raise Refused("read-only mode is on in managed services: no tool action can run until an operator "
                      "sets ACTIONS_READONLY=false")
    can_act, _ = caps(db, email)
    if not can_act:
        raise Refused("you do not have permission to run response actions in managed services", 403)
    r = ActionRequest(client_id=d.client_id, device_id=d.id, action_id=action_id, tool=d.tool, requested_by=email,
                      via=via, reason=reason.strip()[:2000], source_ref=source_ref.strip()[:200])
    r.device, r.client = d, d.client
    db.add(r)
    if spec.danger:
        r.status = "pending"
        r.expires_at = utcnow() + dt.timedelta(minutes=REQUEST_TTL_MINUTES)
    else:
        db.flush()
        _run(db, r, approver="")
        r.decided_by, r.decided_at = email, utcnow()
    db.commit()
    return r


def decide(db: Session, r: ActionRequest, actor: str, approve: bool, note: str = "") -> ActionRequest:
    email, _ = split_actor(actor)
    if r.status != "pending":
        raise Refused(f"this request is already {r.status}" + (f" ({r.decided_by})" if r.decided_by else ""))
    if email == r.requested_by:
        raise Refused("you asked for this one; a second person has to approve it", 403)
    _, can_approve = caps(db, email)
    if not can_approve:
        raise Refused("approving a destructive action needs approval rights in managed services", 403)
    r.decided_by, r.decided_at = email, utcnow()
    if not approve:
        r.status, r.detail = "rejected", (note or "rejected")[:2000]
    else:
        _run(db, r, approver=email)
    db.commit()
    return r
