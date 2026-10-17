"""Execution: carrying out an approved proposal, and only through a module's own
service API. Each executor returns a result dict; the brain records the outcome
in the ledger and on the proposal. A failure never raises; it marks the proposal
failed with the reason so a person can see it. Which executor a proposal uses is
the skill's `executor` name in the catalog (skills.py).
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import metrics, narrative, perception, reach, redact, skills
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


def client_actions(db: Session, client: dict, days: int | None = None, exclude: tuple[str, ...] = ("client_brief", "daily_summary")) -> list[dict]:
    """Every action carried out for one client inside the brief window, each with
    the skill's title and a one-line rationale, redacted for the client's eyes.
    Skills marked client_visible=False (internal business work, and drafts that are
    themselves client communications) are never listed."""
    from .config import settings

    pid, name = client.get("id", ""), client.get("name", "")
    since = utcnow() - dt.timedelta(days=days or settings.client_brief_window_days)
    rows = db.execute(select(Proposal).where(Proposal.status == "executed", Proposal.executed_at >= since)
                      .order_by(Proposal.executed_at.desc())).scalars().all()
    out = []
    for p in rows:
        if p.action in exclude or p.action not in skills.REGISTRY or not skills.get(p.action).client_visible:
            continue
        f, t = p.facts or {}, p.target or {}
        mine = pid and pid in (f.get("platform_client_id"), t.get("platform_client_id"))
        mine = mine or (name and name in (f.get("client"), t.get("client")))
        if not mine:
            continue
        why = (p.rationale or "").strip().split(". ")[0].strip().rstrip(".")
        if len(why) > 200:
            why = why[:200].rsplit(" ", 1)[0] + " ..."
        out.append({"at": p.executed_at.date().isoformat(), "what": skills.get(p.action).title,
                    "why": (why + "." if why and not why.endswith("...") else why), "by": "a Vendetta responder" if p.decided_by else "SABINE"})
    ctx = redact.client_context(db, client)
    return redact.redact_actions(out, client, ctx)


def client_brief(db: Session, p: Proposal) -> dict:
    pid = p.target.get("platform_client_id", "")
    client = next((c for c in perception.clients(db) if c["id"] == pid), {"name": p.target.get("client", ""), "id": pid})
    findings = [f for f in perception.findings(db) if (f.get("subject") or {}).get("platform_client_id") == pid]
    cases = [c for c in perception.cases(db) if (c.get("client") or {}).get("platform_client_id") == pid]
    body, source = narrative.client_brief(client, findings, cases, client_actions(db, client))
    body = redact.redact_for_client(body, client, redact.client_context(db, client))
    b = Brief(kind="client-brief", client=client.get("name", ""), platform_client_id=pid,
              title=f"{client.get('name', '')} brief, {utcnow().date().isoformat()}", body_md=body, source=source)
    db.add(b)
    db.flush()
    return {"ok": True, "detail": f"brief written ({source})", "brief": b.id}


def communications_waiting(db: Session) -> list[dict]:
    """Drafts on the platform that a person has not approved or discarded yet."""
    out = []
    for c in perception.active_clients(db):
        for item in perception.communications(db, c["id"]) or []:
            if item.get("status") == "draft":
                out.append({"client": c["name"], "kind": item.get("kind"), "title": item.get("title"),
                            "source": item.get("source"), "created_at": item.get("created_at")})
    return out


def pages_sent(db: Session, since: dt.datetime) -> list[dict]:
    rows = db.execute(select(Proposal).where(Proposal.action == "page_oncall", Proposal.status == "executed",
                                             Proposal.executed_at >= since)).scalars().all()
    return [{"title": p.title, "client": (p.facts or {}).get("client"), "sent": sorted(((p.result or {}).get("sent") or {}).keys()),
             "at": p.executed_at.isoformat()} for p in rows]


def daily_summary(db: Session, p: Proposal) -> dict:
    from . import brain

    stats = brain.stats(db)
    since = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    recent = db.execute(select(Proposal).where(Proposal.created_at >= since).order_by(Proposal.created_at.desc())).scalars().all()
    pending = [{"title": x.title, "risk": x.risk, "confidence": x.confidence} for x in recent if x.status == "pending"]
    done = [{"title": x.title, "result": (x.result or {}).get("detail", "")} for x in recent if x.status == "executed"]
    body, source = narrative.daily_summary(stats, pending, done, metrics.line(metrics.compute(metrics.rows_from_ledger(db))),
                                           comms=communications_waiting(db), pages=pages_sent(db, since))
    b = Brief(kind="daily-summary", title=f"Daily summary, {utcnow().date().isoformat()}", body_md=body, source=source)
    db.add(b)
    db.flush()
    return {"ok": True, "detail": f"summary written ({source})", "brief": b.id}


# ---------------------------------------------------------------- concierge
def _client(db: Session, p: Proposal) -> dict:
    pid = (p.target or {}).get("platform_client_id", "")
    return perception.client(db, pid) or {"id": pid, "name": (p.target or {}).get("client", "")}


def page_oncall(db: Session, p: Proposal) -> dict:
    t = p.target
    res = reach.post("incident-response", t.get("path", "/api/oncall/page"), t.get("body") or {}, timeout=30.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    sent = (res["data"] or {}).get("sent") or {}
    return {"ok": True, "sent": sent,
            "detail": ("paged via " + ", ".join(sorted(sent))) if sent else "the IR hub has no page channel configured; nothing was sent"}


def journey_suggest(db: Session, p: Proposal) -> dict:
    t = p.target
    client = _client(db, p)
    ctx = redact.client_context(db, client)
    body = {"title": redact.redact_for_client(t["title"], client, ctx)[:200],
            "detail": redact.redact_for_client(t.get("detail", ""), client, ctx), "area": t["area"], "source_ref": t["source_ref"]}
    if t.get("due_on"):
        body["due_on"] = t["due_on"]
    res = reach.post("platform", f"/api/platform/clients/{t['platform_client_id']}/journey", body, timeout=20.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    d = res["data"] or {}
    return {"ok": True, "item": d.get("id"), "created": bool(d.get("created")),
            "detail": "proposed on the Security Journey" if d.get("created") else "already on the Security Journey"}


def journey_progress(db: Session, p: Proposal) -> dict:
    t = p.target
    res = reach.post("platform", f"/api/platform/clients/{t['platform_client_id']}/journey/{t['item_id']}/progress",
                     {"status": t["status"], "note": t.get("note", ""), "source_ref": t.get("source_ref", "")}, timeout=20.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    return {"ok": True, "item": t["item_id"], "status": (res["data"] or {}).get("status", t["status"]),
            "detail": f"journey item marked {t['status'].replace('_', ' ')}"}


def _post_draft(db: Session, p: Proposal, kind: str, title: str, subject: str, body: str, source: str) -> dict:
    t = p.target
    res = reach.post("platform", f"/api/platform/clients/{t['platform_client_id']}/communications",
                     {"kind": kind, "title": title[:300], "subject": subject[:300], "body_md": body, "source_ref": t["source_ref"]},
                     timeout=30.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    d = res["data"] or {}
    # draft=True: a person still approves this on the platform, so the action is not
    # a closed loop and mean time to trusted action does not count it as one.
    return {"ok": True, "draft": True, "communication": d.get("id"), "created": bool(d.get("created")), "narrative": source,
            "detail": ("draft on the platform waiting for approval" if d.get("created") else "draft already on the platform")}


# Finding-model statuses a client portal shows for modules other than MDR.
CLIENT_VISIBLE_STATUSES = ("confirmed", "closed")


def client_visible_finding(f: dict) -> bool:
    """What a client portal shows: an MDR investigation once it is published, and
    another module's finding once it is confirmed or closed. The posture review is a
    client draft, so it is built only from these."""
    if f.get("_module") == "mdr":
        return f.get("published") is True
    return f.get("status") in CLIENT_VISIBLE_STATUSES


def posture_review(db: Session, p: Proposal) -> dict:
    t = p.target
    client = _client(db, p)
    pid = client.get("id", "")
    findings = [f for f in perception.findings(db)
                if (f.get("subject") or {}).get("platform_client_id") == pid and client_visible_finding(f)]
    cases = [c for c in perception.cases(db) if (c.get("client") or {}).get("platform_client_id") == pid]
    journey = perception.journey(db, pid) or []
    month = t.get("month") or utcnow().strftime("%Y-%m")
    body, source = narrative.posture_review(client, month, findings, cases, journey, client_actions(db, client, days=31))
    body = redact.redact_for_client(body, client, redact.client_context(db, client))
    label = dt.datetime.strptime(month + "-01", "%Y-%m-%d").strftime("%B %Y")
    return _post_draft(db, p, "posture_review", f"{client.get('name', '')} posture review, {label}",
                       f"Your security posture review for {label}", body, source)


def client_outreach(db: Session, p: Proposal) -> dict:
    client = _client(db, p)
    subject, body, source = narrative.outreach(p.target.get("reason", ""), client, p.facts or {})
    ctx = redact.client_context(db, client)
    subject = redact.redact_for_client(subject, client, ctx)
    body = redact.redact_for_client(body, client, ctx)
    return _post_draft(db, p, "outreach", subject, subject, body, source)


def suggest_suppression(db: Session, p: Proposal) -> dict:
    t = p.target
    by = p.decided_by or "sabine"
    res = reach.post("mdr", t.get("path", "/api/suppressions"),
                     {"platform_client_id": t["platform_client_id"], "title_contains": t["title_contains"],
                      "tool": t.get("tool") or "", "host": t.get("host") or "",
                      "reason": t.get("reason", "suggested by SABINE"), "days": int(t.get("days") or 30),
                      "created_by": f"sabine (approved by {by})" if p.decided_by else "sabine"}, timeout=20.0)
    if not res["ok"]:
        return {"ok": False, "detail": res["detail"]}
    d = res["data"] or {}
    return {"ok": True, "suppression": d.get("id"), "expires_at": d.get("expires_at"),
            "detail": f"suppression {d.get('id', '')} until {(d.get('expires_at') or '')[:10]}".strip()}


EXECUTORS = {
    "escalate_finding": escalate_finding,
    "roster_sync": roster_sync,
    "raise_work_item": raise_work_item,
    "handoff": handoff,
    "client_brief": client_brief,
    "daily_summary": daily_summary,
    "page_oncall": page_oncall,
    "journey_suggest": journey_suggest,
    "journey_progress": journey_progress,
    "posture_review": posture_review,
    "client_outreach": client_outreach,
    "suggest_suppression": suggest_suppression,
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
