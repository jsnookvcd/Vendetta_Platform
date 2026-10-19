"""Closeout and invoicing.

Every engagement carries a closeout checklist (from its template, or the practice
default). An engagement cannot be closed while items are open unless the PM forces
it, so evidence handling, access removal and billing are not skipped.

Invoicing reads Harvest's uninvoiced report for the engagement's project, then
creates a draft invoice in Harvest: hourly work imports the uninvoiced billable time
and expenses for the period; fixed-fee work becomes one service line for the agreed
amount. The draft stays in Harvest for a person to review and send. This module
never sends an invoice, and drafting one ticks the closeout item that names it.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import harvest
from .db import Engagement, Invoice, utcnow


def _err(msg: str, status: int = 400):
    from .service import ServiceError
    return ServiceError(msg, status)


def closeout(eng: Engagement) -> dict:
    items = eng.closeout or []
    return {"engagement": eng.code, "done": sum(1 for i in items if i.get("done")), "total": len(items),
            "items": [{"number": n + 1, **i} for n, i in enumerate(items)]}


def _item(eng: Engagement, ref) -> int:
    items = eng.closeout or []
    s = str(ref or "").strip()
    if s.isdigit() and 1 <= int(s) <= len(items):
        return int(s) - 1
    matches = [i for i, it in enumerate(items) if s.lower() in it["text"].lower()] if s else []
    if len(matches) == 1:
        return matches[0]
    listing = "; ".join(f"{n + 1}. {it['text']}" for n, it in enumerate(items))
    raise _err(f"'{ref}' does not match one closeout item on {eng.code}: {listing}", 404)


def set_item(db: Session, actor: str, eng: Engagement, ref, done: bool = True) -> dict:
    i = _item(eng, ref)
    items = [dict(x) for x in eng.closeout or []]
    items[i].update(done=bool(done), by=actor if done else "", at=utcnow().isoformat() if done else "")
    eng.closeout = items
    db.flush()
    return closeout(eng)


def add_item(db: Session, actor: str, eng: Engagement, text: str) -> dict:
    if not (text or "").strip():
        raise _err("A closeout item needs text")
    items = [dict(x) for x in eng.closeout or []]
    items.append({"key": f"c{len(items) + 1}", "text": text.strip(), "done": False})
    eng.closeout = items
    db.flush()
    return closeout(eng)


def _period(eng: Engagement, start=None, end=None) -> tuple[dt.date, dt.date]:
    from .service import parse_date
    s = parse_date(start) or eng.starts_on or eng.created_at.date()
    e = parse_date(end) or dt.date.today()
    if s > e:
        raise _err("The invoice period starts after it ends")
    if (e - s).days > 364:
        s = e - dt.timedelta(days=364)
    return s, e


def uninvoiced(db: Session, eng: Engagement, start=None, end=None) -> dict:
    if not eng.harvest_project_id:
        raise _err(f"{eng.code} is not linked to a Harvest project")
    s, e = _period(eng, start, end)
    try:
        row = harvest.uninvoiced(s, e).get(eng.harvest_project_id)
    except harvest.HarvestError as ex:
        raise _err(str(ex), 502) from ex
    return {"engagement": eng.code, "from": s.isoformat(), "to": e.isoformat(),
            "uninvoiced_hours": round(row["hours"], 2) if row else 0.0,
            "uninvoiced_amount": round(row["amount"], 2) if row else 0.0,
            "currency": row["currency"] if row else "USD"}


def draft_invoice(db: Session, actor: str, actor_role: str, eng: Engagement, *, start=None, end=None,
                  summary_type: str = "task", notes: str = "", payment_term: str = "net 30",
                  fixed_amount: float | None = None) -> dict:
    if actor_role != "admin" and actor != eng.pm_email:
        raise _err("Only the engagement's PM or an admin can draft its invoice", 403)
    if not eng.harvest_project_id:
        raise _err(f"{eng.code} is not linked to a Harvest project")
    s, e = _period(eng, start, end)
    if not fixed_amount:
        summary = uninvoiced(db, eng, s, e)
        if summary["uninvoiced_hours"] <= 0 and summary["uninvoiced_amount"] <= 0:
            raise _err(f"Harvest shows nothing uninvoiced on {eng.code} between {s} and {e}", 409)
    subject = f"{eng.code} {eng.name}"
    try:
        client_id = harvest.project_client_id(eng.harvest_project_id)
        inv = harvest.create_draft_invoice(client_id=client_id, project_id=eng.harvest_project_id, start=s, end=e,
                                           subject=subject, notes=notes, summary_type=summary_type,
                                           payment_term=payment_term, fixed_amount=fixed_amount,
                                           fixed_description=f"{eng.name} (fixed fee)")
    except harvest.HarvestError as ex:
        raise _err(str(ex), 502) from ex
    db.add(Invoice(engagement_id=eng.id, harvest_invoice_id=inv["id"], number=inv["number"], amount=inv["amount"],
                   state=inv["state"], period_from=s, period_to=e, created_by=actor))
    items = [dict(x) for x in eng.closeout or []]
    for it in items:
        if "invoice" in it["text"].lower() and not it.get("done"):
            it.update(done=True, by=actor, at=utcnow().isoformat())
    eng.closeout = items
    db.flush()
    return {**inv, "engagement": eng.code, "from": s.isoformat(), "to": e.isoformat(),
            "next": "Review and send the draft in Harvest; this tool does not send invoices."}


def invoices_for(db: Session, eng: Engagement) -> list[dict]:
    return [{"harvest_invoice_id": i.harvest_invoice_id, "number": i.number, "amount": i.amount, "state": i.state,
             "from": i.period_from.isoformat() if i.period_from else None,
             "to": i.period_to.isoformat() if i.period_to else None, "created_by": i.created_by,
             "created_at": i.created_at.isoformat()}
            for i in db.execute(select(Invoice).where(Invoice.engagement_id == eng.id)
                                .order_by(Invoice.created_at.desc())).scalars()]
