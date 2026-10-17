"""The announcement feed. Every POLL_INTERVAL_SECONDS:

- new IR cases, from anywhere (escalations, the client portal, the console, MDR),
  are announced once in SLACK_IR_CHANNEL with buttons to open a war room;
- a war room hears when its case changed outside Slack (status, severity, lead),
  and its topic and pinned card follow;
- SABINE proposals waiting on a person are posted once in SLACK_SABINE_CHANNEL
  with Approve and Reject, and the message is updated when the proposal is decided
  anywhere, Slack or console.

On the first run against an empty table the feed records what already exists
without posting it, so turning the responder on does not flood a channel with
every open case and proposal.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time

from sqlalchemy import select

from . import blocks, reach, responder, slack
from .config import settings
from .db import Posted, SessionLocal, WarRoom

log = logging.getLogger(__name__)
LAST: dict = {"at": None, "ok": None, "detail": "never run", "cases": 0, "proposals": 0}


def _seeding(db, kind: str) -> bool:
    """True exactly once per kind: the first time the feed runs against an empty
    table. A marker row records that the seed happened, so a first run that found
    nothing does not make the next real item look like history."""
    if db.execute(select(Posted.id).where(Posted.kind == kind).limit(1)).first() is not None:
        return False
    db.add(Posted(kind=kind, ref="__seeded__", channel="", ts="", state="seed"))
    db.commit()
    return True


def cases(db) -> int:
    r = reach.get(responder.IR, "/api/ir-cases", params={"status": "active"})
    if not r["ok"]:
        raise RuntimeError(f"IR hub: {r['detail']}")
    active = r["data"] or []
    posted = 0
    seed = _seeding(db, "case")
    by_number = {c["number"]: c for c in active}
    for c in active:
        if db.execute(select(Posted).where(Posted.kind == "case", Posted.ref == c["number"])).scalar_one_or_none():
            continue
        if seed:
            db.add(Posted(kind="case", ref=c["number"], channel="", ts=""))
            continue
        responder._announce_case(db, c, responder.room_for_case(db, c["number"]))
        posted += 1
    db.commit()
    # War rooms follow changes made outside Slack.
    for room in db.execute(select(WarRoom).where(WarRoom.active.is_(True))).scalars().all():
        c = by_number.get(room.case_number)
        if c is None:
            continue
        snap = responder._snapshot(c)
        prev = responder.room_last.get(room.id)
        responder.room_last[room.id] = snap
        if prev is None or prev == snap:
            continue
        old = dict(zip(("severity", "status", "lead"), prev.split("|", 2)))
        changes = [f"{k} {old.get(k) or 'unassigned'} to {c.get(k) or 'unassigned'}"
                   for k in ("status", "severity", "lead") if (old.get(k) or "") != (c.get(k) or "")]
        if changes:
            responder.refresh_room(db, room, c)
            slack.try_call("chat.postMessage", channel=room.channel_id,
                           text=f":arrows_counterclockwise: {c['number']} changed in the IR hub: " + "; ".join(changes) + ".")
    return posted


def proposals(db) -> int:
    r = reach.get(responder.SABINE, "/api/proposals", params={"status": "pending"})
    if not r["ok"]:
        raise RuntimeError(f"SABINE: {r['detail']}")
    pending = r["data"] or []
    seed = _seeding(db, "proposal")
    posted = 0
    ids = set()
    for p in pending:
        ids.add(p["id"])
        if db.execute(select(Posted).where(Posted.kind == "proposal", Posted.ref == p["id"])).scalar_one_or_none():
            continue
        row = Posted(kind="proposal", ref=p["id"], channel="" if seed else settings.slack_sabine_channel,
                     state="pending")
        db.add(row)
        db.commit()
        if seed:
            continue
        res = slack.try_call("chat.postMessage", channel=settings.slack_sabine_channel,
                             text=f"SABINE proposes: {p.get('title')}",
                             blocks=blocks.proposal_card(p, console_url=responder._sabine_url(p["id"])))
        if res:
            row.ts = res.get("ts", "")
            db.commit()
            posted += 1
    # Anything we posted that is no longer pending was decided somewhere: say so on the message.
    open_rows = db.execute(select(Posted).where(Posted.kind == "proposal", Posted.state == "pending",
                                                Posted.ts != "")).scalars().all()
    stale = [row for row in open_rows if row.ref not in ids]
    if stale:
        allr = reach.get(responder.SABINE, "/api/proposals", params={"status": "all"})
        known = {p["id"]: p for p in (allr["data"] or [])} if allr["ok"] else {}
        for row in stale:
            p = known.get(row.ref)
            if p is None or p.get("status") == "pending":
                continue
            who = f" by {p['decided_by']}" if p.get("decided_by") else ""
            decided = f"{p['status'].capitalize()}{who}."
            slack.try_call("chat.update", channel=row.channel, ts=row.ts, text=decided,
                           blocks=blocks.proposal_card(p, console_url=responder._sabine_url(p["id"]), decided=decided))
            row.state = p["status"]
        db.commit()
    return posted


def cycle() -> dict:
    db = SessionLocal()
    out = {"cases": 0, "proposals": 0, "errors": []}
    try:
        if settings.slack_ir_channel or db.execute(select(WarRoom.id).where(WarRoom.active.is_(True)).limit(1)).first():
            try:
                out["cases"] = cases(db)
            except Exception as e:  # noqa: BLE001
                db.rollback()
                out["errors"].append(str(e))
        if settings.slack_sabine_channel:
            try:
                out["proposals"] = proposals(db)
            except Exception as e:  # noqa: BLE001
                db.rollback()
                out["errors"].append(str(e))
    finally:
        db.close()
    LAST.update(at=dt.datetime.now(dt.timezone.utc), ok=not out["errors"],
                detail="; ".join(out["errors"]) or "ok", cases=out["cases"], proposals=out["proposals"])
    return out


def start() -> None:
    if settings.poll_interval_seconds <= 0 or not slack.configured():
        return

    def _loop():
        time.sleep(10)
        while True:
            try:
                cycle()
            except Exception:  # noqa: BLE001
                log.exception("feed cycle failed")
            time.sleep(settings.poll_interval_seconds)

    threading.Thread(target=_loop, name="slack-feed", daemon=True).start()
