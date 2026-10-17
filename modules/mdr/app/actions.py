"""Analyst actions on an investigation, each written to its signed timeline.

MDR records and recommends; it never touches a client host. Containment is
prepared here (the recommended action, who prepared it, and the managed-services
alert to act on) and carried out by a responder in managed-services under that
module's approval rules.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from . import hub
from .config import RESPONSE_NAMES, RESPONSES, VERDICT_NAMES, VERDICTS, settings
from .db import Client, Investigation, Suppression, record, utcnow


class ActionError(ValueError):
    pass


def acknowledge(db: Session, inv: Investigation, actor: str) -> bool:
    if inv.acknowledged_at:
        return False
    inv.acknowledged_at, inv.acknowledged_by = utcnow(), actor
    if inv.status == "new":
        inv.status = "investigating"
    record(db, inv, "acknowledged", actor, f"Acknowledged by {actor}.", client_visible=True)
    db.commit()
    return True


def set_verdict(db: Session, inv: Investigation, verdict: str, actor: str, note: str = "") -> None:
    if verdict not in VERDICTS:
        raise ActionError("unknown verdict")
    prev = inv.verdict
    if prev == verdict:
        return
    inv.verdict = verdict
    if not inv.acknowledged_at:
        inv.acknowledged_at, inv.acknowledged_by = utcnow(), actor
    if inv.status == "new":
        inv.status = "investigating"
    record(db, inv, "verdict", actor, f"Verdict {VERDICT_NAMES[prev]} -> {VERDICT_NAMES[verdict]}."
           + (f" {note}" if note else ""), {"from": prev, "to": verdict}, client_visible=True)
    db.commit()


def add_note(db: Session, inv: Investigation, text: str, actor: str) -> None:
    text = (text or "").strip()
    if not text:
        raise ActionError("note is empty")
    record(db, inv, "note", actor, text[:4000])
    db.commit()


def publish(db: Session, inv: Investigation, summary: str, published: bool, actor: str) -> None:
    summary = (summary or "").strip()
    if published and not summary:
        raise ActionError("write the client summary before publishing")
    was = inv.published
    inv.client_summary = summary[:4000]
    inv.published = bool(published)
    if inv.published and not was:
        record(db, inv, "published", actor, "Shared with the client portal.", {"summary": inv.client_summary})
    elif was and not inv.published:
        record(db, inv, "unpublished", actor, "Withdrawn from the client portal.")
    else:
        record(db, inv, "summary", actor, "Client summary updated.", {"summary": inv.client_summary})
    db.commit()


def mark_contained(db: Session, inv: Investigation, actor: str, note: str = "") -> None:
    if inv.status == "closed":
        raise ActionError("investigation is closed")
    if inv.contained_at:
        return
    inv.contained_at = utcnow()
    inv.status = "contained"
    if not inv.acknowledged_at:
        inv.acknowledged_at, inv.acknowledged_by = inv.contained_at, actor
    record(db, inv, "contained", actor, "Marked contained." + (f" {note}" if note else ""), client_visible=True)
    db.commit()


def close(db: Session, inv: Investigation, actor: str, verdict: str = "", note: str = "") -> None:
    if inv.status == "closed":
        return
    if verdict:
        if verdict not in VERDICTS:
            raise ActionError("unknown verdict")
        if verdict != inv.verdict:
            set_verdict(db, inv, verdict, actor)
    inv.status = "closed"
    inv.closed_at = utcnow()
    if not inv.acknowledged_at:
        inv.acknowledged_at, inv.acknowledged_by = inv.closed_at, actor
    record(db, inv, "closed", actor, f"Closed as {VERDICT_NAMES.get(inv.verdict, inv.verdict)}."
           + (f" {note}" if note else ""), {"verdict": inv.verdict}, client_visible=True)
    db.commit()


def reopen(db: Session, inv: Investigation, actor: str, note: str = "") -> None:
    if inv.status != "closed":
        return
    inv.status = "contained" if inv.contained_at else "investigating"
    inv.closed_at = None
    record(db, inv, "reopened", actor, "Reopened." + (f" {note}" if note else ""), client_visible=True)
    db.commit()


def create_suppression(db: Session, client: Client, *, tool: str = "", title_contains: str = "", host: str = "",
                       reason: str, days: int, created_by: str,
                       source_investigation_id: str | None = None) -> Suppression:
    reason = (reason or "").strip()
    if not reason:
        raise ActionError("a reason is required")
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise ActionError("days must be a number from 1 to 90")
    if not 1 <= days <= 90:
        raise ActionError("days must be from 1 to 90")
    tool, title_contains, host = (tool or "").strip().lower(), (title_contains or "").strip(), (host or "").strip()
    if not (tool or title_contains or host):
        raise ActionError("a suppression needs a tool, a title fragment or a host")
    sup = Suppression(client_id=client.id, platform_client_id=client.platform_client_id or "", tool=tool[:30],
                      title_contains=title_contains[:400], host=host[:255], reason=reason[:2000],
                      expires_at=utcnow() + dt.timedelta(days=days), created_by=(created_by or "")[:320],
                      source_investigation_id=source_investigation_id)
    db.add(sup)
    db.flush()
    return sup


def noise(db: Session, inv: Investigation, actor: str, reason: str, days: int | None = None,
          tool: str | None = None, title_contains: str | None = None, host: str | None = None) -> Suppression:
    """"This was noise": close as false positive and suppress the pattern for this
    client. The scope defaults to the latest signal's tool, title and host."""
    latest = inv.latest_signal()
    if tool is None:
        tool = latest.tool if latest else ""
    if title_contains is None:
        title_contains = latest.title if latest else ""
    if host is None:
        host = inv.host or (latest.host if latest else "")
    sup = create_suppression(db, inv.client, tool=tool, title_contains=title_contains, host=host, reason=reason,
                             days=days or settings.noise_suppression_days, created_by=actor,
                             source_investigation_id=inv.id)
    record(db, inv, "suppression_created", actor,
           f"Marked as noise; suppression {sup.id[:8]} for {sup.expires_at.date().isoformat()}: {sup.reason}",
           {"suppression": sup.id, "tool": sup.tool, "title_contains": sup.title_contains, "host": sup.host,
            "expires_at": sup.expires_at.isoformat()})
    db.flush()
    close(db, inv, actor, verdict="false_positive", note="This was noise.")
    return sup


def prepare_containment(db: Session, inv: Investigation, action: str, actor: str, note: str = "") -> dict:
    """Record the recommended response and hand the responder to the managed-services
    alert. Returns {action, host, alert_ref, link}."""
    if action not in RESPONSES or action == "none":
        raise ActionError("choose a containment action")
    if inv.status == "closed":
        raise ActionError("investigation is closed")
    ref, link = hub.alert_ref(inv), hub.alert_link(inv)
    inv.response = action
    inv.response_note = (note or "").strip()[:2000]
    inv.response_prepared_at, inv.response_prepared_by = utcnow(), actor
    if not inv.acknowledged_at:
        inv.acknowledged_at, inv.acknowledged_by = inv.response_prepared_at, actor
    if inv.status == "new":
        inv.status = "investigating"
    record(db, inv, "containment_prepared", actor,
           f"Containment prepared: {RESPONSE_NAMES[action]}"
           + (f" on {inv.host}" if inv.host else "") + (f" via managed-services alert {ref}" if ref else "")
           + (f". {inv.response_note}" if inv.response_note else "."),
           {"action": action, "host": inv.host, "alert_ref": ref, "link": link})
    db.commit()
    return {"action": action, "host": inv.host, "alert_ref": ref, "link": link}
