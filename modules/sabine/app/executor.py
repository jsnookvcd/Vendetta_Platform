"""Execution: carrying out an approved proposal, and only through a module's own
service API. Each executor returns a result dict; the brain records the outcome
in the ledger and on the proposal. A failure never raises; it marks the proposal
failed with the reason so a person can see it. Which executor a proposal uses is
the skill's `executor` name in the catalog (skills.py).
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import metrics, narrative, perception, reach, skills
from .db import Brief, Proposal, WorkItem, utcnow

log = logging.getLogger(__name__)


def escalate_finding(db: Session, p: Proposal) -> dict:
    t = p.target
    res = reach.post(t["module"], t["path"], timeout=40.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"] or (res["data"] or {}).get("reason", "escalation refused")}
    data = res["data"] or {}
    return {"ok": True, "detail": f"case {data.get('case', '')}{' (linked)' if data.get('linked') else ''}",
            "case": data.get("case"), "linked": data.get("linked")}


def roster_sync(db: Session, p: Proposal) -> dict:
    res = reach.post(p.target["module"], "/api/provision/sync", timeout=40.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    d = res["data"] or {}
    return {"ok": True, "detail": ", ".join(f"{k} {d[k]}" for k in ("roster", "added", "updated", "deactivated", "staff") if k in d)}


def raise_work_item(db: Session, p: Proposal) -> dict:
    """Correlation notes, nudges and readiness fixes become SABINE-owned queue items."""
    t = p.target
    key = f"sabine:{p.action}:{p.key}"
    w = db.execute(select(WorkItem).where(WorkItem.key == key)).scalar_one_or_none()
    if w is None:
        w = WorkItem(key=key, source="sabine", kind=t.get("kind", p.action), domain=p.domain, title=p.title[:400],
                     client=t.get("client", ""), platform_client_id=t.get("platform_client_id", ""),
                     severity=t.get("severity", "medium"), link=t.get("link", ""),
                     payload={"proposal": p.id, "rationale": p.rationale, "facts": p.facts})
        db.add(w)
    else:
        w.state, w.last_seen, w.title = ("open" if w.state == "gone" else w.state), utcnow(), p.title[:400]
        w.payload = {"proposal": p.id, "rationale": p.rationale, "facts": p.facts}
    db.flush()
    return {"ok": True, "detail": "queued", "work_item": w.id}


def handoff(db: Session, p: Proposal) -> dict:
    """A high-risk action is never executed by SABINE; approving it records the
    decision and queues the hand-off to the module where a person acts."""
    r = raise_work_item(db, p)
    r["detail"] = "handed to a responder in " + p.target.get("module", "the module")
    return r


def client_brief(db: Session, p: Proposal) -> dict:
    pid = p.target.get("platform_client_id", "")
    client = next((c for c in perception.clients(db) if c["id"] == pid), {"name": p.target.get("client", ""), "id": pid})
    findings = [f for f in perception.findings(db) if (f.get("subject") or {}).get("platform_client_id") == pid]
    cases = [c for c in perception.cases(db) if (c.get("client") or {}).get("platform_client_id") == pid]
    body, source = narrative.client_brief(client, findings, cases)
    b = Brief(kind="client-brief", client=client.get("name", ""), platform_client_id=pid,
              title=f"{client.get('name', '')} brief, {utcnow().date().isoformat()}", body_md=body, source=source)
    db.add(b)
    db.flush()
    return {"ok": True, "detail": f"brief written ({source})", "brief": b.id}


def daily_summary(db: Session, p: Proposal) -> dict:
    from . import brain

    stats = brain.stats(db)
    since = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    recent = db.execute(select(Proposal).where(Proposal.created_at >= since).order_by(Proposal.created_at.desc())).scalars().all()
    pending = [{"title": x.title, "risk": x.risk, "confidence": x.confidence} for x in recent if x.status == "pending"]
    done = [{"title": x.title, "result": (x.result or {}).get("detail", "")} for x in recent if x.status == "executed"]
    body, source = narrative.daily_summary(stats, pending, done, metrics.line(metrics.compute(metrics.rows_from_ledger(db))))
    b = Brief(kind="daily-summary", title=f"Daily summary, {utcnow().date().isoformat()}", body_md=body, source=source)
    db.add(b)
    db.flush()
    return {"ok": True, "detail": f"summary written ({source})", "brief": b.id}


EXECUTORS = {
    "escalate_finding": escalate_finding,
    "roster_sync": roster_sync,
    "raise_work_item": raise_work_item,
    "handoff": handoff,
    "client_brief": client_brief,
    "daily_summary": daily_summary,
}


def execute(db: Session, p: Proposal) -> dict:
    fn = EXECUTORS[skills.get(p.action).executor]
    try:
        res = fn(db, p)
    except Exception as e:  # noqa: BLE001
        log.exception("executor %s failed", p.action)
        res = {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}
    p.result = res
    p.executed_at = utcnow()
    p.status = "executed" if res.get("ok") else "failed"
    db.commit()
    return res
