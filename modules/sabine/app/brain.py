"""The cycle: perceive, reason, act, record. And the decisions people make.

One cycle:
1. observe every module and the control plane (perception.observe);
2. rebuild the operator queue (perception.build_queue);
3. run the rules (reasoner.run), which raise proposals at the autonomy level the
   policy sets;
4. execute the proposals whose level is auto; leave the rest pending for a person;
5. append what happened to the ledger.

A person approves or rejects a pending proposal from the console or the API; an
approval executes it right then. A high-risk proposal's "execution" is a hand-off
into the module where the person acts.
"""
from __future__ import annotations

import logging
import threading
import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import executor, ledger, perception, policy, reasoner
from .config import settings
from .db import Proposal, SessionLocal, WorkItem, utcnow

log = logging.getLogger(__name__)
_LOCK = threading.Lock()
LAST: dict = {"at": None, "ok": None, "detail": "never run", "seen": {}, "queue": {}, "proposed": 0, "executed": 0,
              "line": ""}


def cycle(db: Session) -> dict:
    """Run one full cycle. Safe to call from the scheduler, the console or the API;
    concurrent calls serialize."""
    with _LOCK:
        started = utcnow()
        try:
            seen = perception.observe(db)
            queue = perception.build_queue(db)
            reasoner.expire(db)
            proposals = reasoner.run(db)
            executed = 0
            for p in proposals:
                ledger.append(db, "proposal", settings.actor_name, f"{p.action}: {p.title}",
                              {"facts": p.facts, "target": p.target, "confidence": p.confidence,
                               "risk": p.risk, "autonomy": p.autonomy, "rationale": p.rationale}, ref=p.id)
                if p.autonomy == "auto":
                    res = executor.execute(db, p)
                    ledger.append(db, "action", settings.actor_name, f"{p.action} {'done' if res.get('ok') else 'failed'}: {p.title}",
                                  {"result": res, "autonomy": "auto", "action": p.action}, ref=p.id)
                    executed += 1
            summary = {"seen": seen, "queue": queue, "proposed": len(proposals), "executed": executed,
                       "duration_s": round((utcnow() - started).total_seconds(), 1)}
            ledger.append(db, "cycle", settings.actor_name,
                          f"cycle: {sum(1 for v in seen.values() if v)}/{len(seen)} sources, "
                          f"{queue.get('finding', 0)} findings, {queue.get('case', 0)} cases, "
                          f"{len(proposals)} proposed, {executed} done", summary)
            from . import narrative

            LAST.update(at=utcnow(), ok=True, detail="ok", **summary)
            LAST["line"] = narrative.cycle_line(stats(db), summary)
            return summary
        except Exception as e:  # noqa: BLE001
            log.exception("cycle failed")
            db.rollback()
            LAST.update(at=utcnow(), ok=False, detail=f"{type(e).__name__}: {e}"[:300])
            raise


def decide(db: Session, p: Proposal, actor: str, approve: bool, note: str = "") -> dict:
    if p.status != "pending":
        return {"ok": False, "detail": f"proposal is {p.status}"}
    p.decided_by, p.decided_at, p.decision_note = actor, utcnow(), note[:2000]
    if not approve:
        p.status = "rejected"
        db.commit()
        ledger.append(db, "decision", actor, f"rejected: {p.title}", {"note": note}, ref=p.id)
        return {"ok": True, "detail": "rejected"}
    p.status = "approved"
    db.commit()
    ledger.append(db, "decision", actor, f"approved: {p.title}", {"note": note}, ref=p.id)
    res = executor.execute(db, p)
    ledger.append(db, "action", settings.actor_name, f"{p.action} {'done' if res.get('ok') else 'failed'}: {p.title}",
                  {"result": res, "autonomy": "approved", "by": actor, "action": p.action}, ref=p.id)
    return res


def stats(db: Session) -> dict:
    open_items = db.execute(select(WorkItem.domain, func.count(WorkItem.id)).where(WorkItem.state.in_(("open", "claimed")))
                            .group_by(WorkItem.domain)).all()
    by = {d: n for d, n in open_items}
    pending = db.scalar(select(func.count(Proposal.id)).where(Proposal.status == "pending")) or 0
    return {"open": sum(by.values()), "soc": by.get("soc", 0), "admin": by.get("admin", 0),
            "services": by.get("services", 0), "pending": pending}


def picture(db: Session) -> dict:
    """What SABINE knows right now, compact, for the Ask page."""
    snaps = perception.snapshots(db)
    return {
        "open_items": stats(db)["open"],
        "pending_proposals": stats(db)["pending"],
        "clients": [c["name"] for c in perception.clients(db)],
        "modules": {k.split(":", 1)[1]: ("ok" if s.ok else s.detail) for k, s in snaps.items() if k.startswith("module:")},
        "findings_by_severity": _count(perception.findings(db), "severity"),
        "open_cases": [{"number": c.get("number"), "client": (c.get("client") or {}).get("name"), "severity": c.get("severity")}
                       for c in perception.cases(db)],
        "readiness_ready": (perception.readiness(db) or {}).get("ready"),
        "top_queue": [{"title": w.title, "severity": w.severity, "domain": w.domain, "client": w.client}
                      for w in db.execute(select(WorkItem).where(WorkItem.state == "open")
                                          .order_by(WorkItem.severity.desc(), WorkItem.first_seen).limit(15)).scalars().all()],
    }


def _count(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        out[r.get(key, "?")] = out.get(r.get(key, "?"), 0) + 1
    return out


def start_scheduler() -> None:
    interval = int(settings.cycle_interval_seconds or 0)
    if interval <= 0:
        return

    def _loop():
        time.sleep(10)
        while True:
            db = SessionLocal()
            try:
                cycle(db)
            except Exception:  # noqa: BLE001
                pass
            finally:
                db.close()
            time.sleep(interval)

    threading.Thread(target=_loop, name="sabine-cycle", daemon=True).start()
