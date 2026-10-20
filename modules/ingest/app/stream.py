"""Streaming detection over normalized events.

Each pass reads the events not yet evaluated (Event.detected is false), in seq
order, and marks them evaluated in the same transaction as the detections they
raise. A flag rather than a cursor: an event whose insert commits after a later one
is still evaluated. For each event the pass:

- turns every vendor detection (an OCSF Detection Finding from a source whose mapper
  is the vendor's own alerting) into one Detection per vendor finding id, updated in
  place as the vendor updates or closes it, so a status change never opens a second
  detection;
- runs every enabled Sigma rule. A rule without a threshold raises one Detection per
  (rule, tenant, host or user) and folds further matches inside the rule's window
  (one hour by default) into it. A threshold rule records each match and raises a
  Detection when the count, or the count of distinct values, inside the rule's
  timeframe reaches the threshold.

Detections are served at GET /api/findings in the shared finding model, where MDR
reads them as signals next to the managed-services alerts. Each carries the ids of
the events behind it, and each event's signed receipt proves it arrived unaltered.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import mappers, ocsf, sigma
from .config import settings
from .db import Detection, Event, RuleHit, SigmaRule, utcnow

log = logging.getLogger(__name__)

_LOCK_KEY = 880_901
CHUNK = 2000
DEFAULT_WINDOW = dt.timedelta(hours=1)
MAX_EVENT_IDS = 500
DRY_RUN_SECONDS = 10

# Source key to the tool name MDR's rules match on (the finding's `reason`).
TOOL_OF = {
    "crowdstrike_alerts": "crowdstrike", "crowdstrike_fdr": "crowdstrike", "sentinelone_threats": "sentinelone",
    "huntress_incidents": "huntress", "defender_alerts": "defender", "entra_signins": "entra",
    "entra_audit": "entra", "cloudtrail": "aws", "guardduty": "aws", "okta_system_log": "okta",
    "m365_audit": "m365", "google_workspace": "google", "cef": "network",
}

LAST: dict = {"at": None, "ok": None, "detail": "never run", "summary": None}

_compiled: dict[tuple[str, int], sigma.Rule] = {}


def tool_of(source: str) -> str:
    return TOOL_OF.get(source, source.split("_")[0])


def load_rules(db: Session) -> list[tuple[SigmaRule, sigma.Rule]]:
    out = []
    for r in db.execute(select(SigmaRule).where(SigmaRule.enabled.is_(True))).scalars().all():
        key = (r.id, r.version)
        if key not in _compiled:
            try:
                _compiled[key] = sigma.compile(r.body)
            except sigma.SigmaError as e:
                log.warning("sigma rule %s v%s does not compile: %s", r.id, r.version, e)
                continue
        out.append((r, _compiled[key]))
    return out


def _append(det: Detection, ev: Event) -> None:
    ids = list(det.event_ids or [])
    if ev.id not in ids:
        ids.append(ev.id)
        if len(ids) > MAX_EVENT_IDS:
            ids = ids[:10] + ids[-(MAX_EVENT_IDS - 10):]
    det.event_ids = ids
    det.count = (det.count or 0) + 1
    if ev.time > det.last_event_at:
        det.last_event_at = ev.time
    if ev.time < det.first_event_at:
        det.first_event_at = ev.time
    det.updated_at = utcnow()


def _vendor(db: Session, ev: Event) -> tuple[Detection, bool]:
    e = ev.event
    uid = str(ocsf.get_path(e, "finding_info.uid") or ev.id)[:250]
    group = f"{ev.source}:{uid}"
    det = db.execute(select(Detection).where(Detection.tenant == ev.tenant, Detection.kind == "vendor",
                                             Detection.group_key == group)).scalar_one_or_none()
    created = det is None
    if created:
        det = Detection(tenant=ev.tenant, client_id=ev.client_id, kind="vendor", source=ev.source,
                        rule_id="", rule_title="", group_key=group, event_ids=[], count=0, status="new", note="",
                        first_event_at=ev.time, last_event_at=ev.time)
        db.add(det)
    attacks = ocsf.get_path(e, "finding_info.attacks.technique.uid") or []
    det.mitre = sorted({str(a) for a in (attacks if isinstance(attacks, list) else [attacks])})
    det.severity = ocsf.finding_severity(int(ev.severity_id or 0))
    det.title = (ocsf.get_path(e, "finding_info.title") or ev.title or "Vendor detection")[:600]
    det.host, det.user = ev.host, ev.user
    if e.get("activity_id") == 3 and det.status in ("new", "reviewing"):
        det.status = "closed"
        det.note = (det.note + "\n" if det.note else "") + f"Closed at the source ({ev.source})."
    _append(det, ev)
    return det, created


def _group(ev: Event) -> str:
    return (ev.host or ev.user or "")[:300]


def _sigma_single(db: Session, rule: SigmaRule, comp: sigma.Rule, ev: Event) -> tuple[Detection, bool]:
    window = dt.timedelta(seconds=comp.timeframe_seconds) if comp.timeframe_seconds else DEFAULT_WINDOW
    group = _group(ev)
    det = db.execute(select(Detection).where(
        Detection.tenant == ev.tenant, Detection.kind == "sigma", Detection.rule_id == rule.id,
        Detection.group_key == group, Detection.status.in_(("new", "reviewing", "confirmed")),
        Detection.last_event_at >= ev.time - window).order_by(Detection.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    created = det is None
    if created:
        det = _new_sigma(rule, comp, ev, group)
        db.add(det)
    _append(det, ev)
    return det, created


def _new_sigma(rule: SigmaRule, comp: sigma.Rule, ev: Event, group: str) -> Detection:
    subject = ev.host or ev.user or ev.src_ip
    return Detection(tenant=ev.tenant, client_id=ev.client_id, kind="sigma", source=ev.source, rule_id=rule.id,
                     rule_title=comp.title[:300], severity=comp.severity(), status="new",
                     title=(f"{comp.title} ({subject})" if subject else comp.title)[:600], host=ev.host,
                     user=ev.user, group_key=group, event_ids=[], count=0, mitre=list(comp.mitre),
                     first_event_at=ev.time, last_event_at=ev.time)


def _sigma_threshold(db: Session, rule: SigmaRule, comp: sigma.Rule, ev: Event) -> tuple[Detection | None, bool]:
    th = comp.threshold or {}
    group = comp.group_key(ev.event)[:300]
    distinct = comp.distinct_value(ev.event)[:300] if th.get("distinct") else ""
    db.add(RuleHit(rule_id=rule.id, tenant=ev.tenant, group_key=group, distinct_value=distinct,
                   event_id=ev.id, time=ev.time))
    db.flush()
    since = ev.time - dt.timedelta(seconds=comp.timeframe_seconds or 600)
    base = select(RuleHit).where(RuleHit.rule_id == rule.id, RuleHit.tenant == ev.tenant,
                                 RuleHit.group_key == group, RuleHit.time >= since, RuleHit.time <= ev.time)
    sq = base.subquery()
    if th.get("distinct"):
        n = db.scalar(select(func.count(func.distinct(sq.c.distinct_value)))) or 0
    else:
        n = db.scalar(select(func.count()).select_from(sq)) or 0
    # An open detection for this group inside the window absorbs further matches.
    det = db.execute(select(Detection).where(
        Detection.tenant == ev.tenant, Detection.kind == "sigma", Detection.rule_id == rule.id,
        Detection.group_key == group, Detection.status.in_(("new", "reviewing", "confirmed")),
        Detection.last_event_at >= since).order_by(Detection.created_at.desc()).limit(1)).scalar_one_or_none()
    if det is not None:
        _append(det, ev)
        return det, False
    if n < int(th.get("count") or 1):
        return None, False
    det = _new_sigma(rule, comp, ev, group)
    label = group.replace("|", ", ") or "this tenant"
    det.title = f"{comp.title} ({label}, {n} in {comp.timeframe_seconds // 60 or 1} min)"[:600]
    db.add(det)
    hits = db.execute(base.order_by(RuleHit.time)).scalars().all()
    det.event_ids = [h.event_id for h in hits][-MAX_EVENT_IDS:]
    det.count = len(hits)
    det.first_event_at = hits[0].time if hits else ev.time
    det.last_event_at = ev.time
    return det, True


def run(db: Session, limit_chunks: int = 50) -> dict:
    """One detection pass. Commits per chunk. Returns counts."""
    # One pass at a time across every process sharing this database.
    if not db.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_KEY}).scalar():
        return {"skipped": "another detection pass is running"}
    try:
        return _run(db, limit_chunks)
    finally:
        db.rollback()
        db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_KEY})
        db.commit()


def _run(db: Session, limit_chunks: int) -> dict:
    rules = load_rules(db)
    summary = {"events": 0, "vendor_new": 0, "vendor_updated": 0, "sigma_new": 0, "sigma_matches": 0}
    vendor_sources = {m.key for m in mappers.all_mappers() if m.detection}
    for _ in range(limit_chunks):
        evs = db.execute(select(Event).where(Event.detected.is_(False)).order_by(Event.seq).limit(CHUNK)
                         ).scalars().all()
        if not evs:
            break
        hits_by_rule: dict[str, int] = {}
        for ev in evs:
            summary["events"] += 1
            if ev.source in vendor_sources and ev.class_uid == 2004:
                _, created = _vendor(db, ev)
                summary["vendor_new" if created else "vendor_updated"] += 1
            for rule, comp in rules:
                try:
                    if not comp.matches(ev.event):
                        continue
                except Exception:  # noqa: BLE001 - one bad rule must not stop detection
                    log.exception("sigma rule %s failed on event %s", rule.id, ev.id)
                    continue
                summary["sigma_matches"] += 1
                hits_by_rule[rule.id] = hits_by_rule.get(rule.id, 0) + 1
                if comp.threshold:
                    _, created = _sigma_threshold(db, rule, comp, ev)
                else:
                    _, created = _sigma_single(db, rule, comp, ev)
                summary["sigma_new"] += int(created)
            db.flush()
        for rid, n in hits_by_rule.items():
            r = db.get(SigmaRule, rid)
            if r is not None:
                r.hits_total = (r.hits_total or 0) + n
        for ev in evs:
            ev.detected = True
        db.commit()
    _trim_hits(db, rules)
    LAST.update(at=utcnow(), ok=True, detail="ok", summary=summary)
    return summary


def _trim_hits(db: Session, rules) -> None:
    # By insert time: a hit for a backfilled or old-dated event must survive long
    # enough to be counted with its neighbours.
    widest = max([c.timeframe_seconds for _, c in rules if c.threshold] + [3600])
    db.execute(RuleHit.__table__.delete().where(
        RuleHit.created_at < utcnow() - dt.timedelta(seconds=widest * 2 + 86400)))
    db.commit()


def test_rule(db: Session, comp: sigma.Rule, tenant: str | None = None, limit: int = 5000) -> dict:
    """Run a compiled rule over recent stored events without recording anything, so
    an admin sees what it would have matched before saving it."""
    q = select(Event).order_by(Event.seq.desc()).limit(limit)
    if tenant:
        q = q.where(Event.tenant == tenant)
    matched = []
    scanned = 0
    started = time.monotonic()
    for ev in db.execute(q).scalars():
        if time.monotonic() - started > DRY_RUN_SECONDS:
            return {"scanned": scanned, "matched": matched[:50], "count": len(matched),
                    "error": f"stopped after {DRY_RUN_SECONDS} seconds; the rule is too slow to save as written"}
        scanned += 1
        try:
            if comp.matches(ev.event):
                matched.append({"id": ev.id, "tenant": ev.tenant, "time": ev.time.isoformat(), "title": ev.title,
                                "host": ev.host, "user": ev.user, "source": ev.source})
        except Exception:  # noqa: BLE001
            return {"scanned": scanned, "matched": matched[:50], "count": len(matched),
                    "error": "the rule raised an error on a stored event"}
    return {"scanned": scanned, "matched": matched[:50], "count": len(matched), "error": ""}


def state() -> dict:
    return {"last_ok": LAST["ok"], "last_at": LAST["at"].isoformat() if LAST["at"] else None,
            "detail": LAST["detail"], "summary": LAST["summary"],
            "interval_seconds": int(settings.stream_interval_seconds or 0)}


def start_scheduler(session_factory) -> None:
    interval = int(settings.stream_interval_seconds or 0)
    if interval <= 0:
        return

    def loop():
        while True:
            time.sleep(interval)
            db = session_factory()
            try:
                run(db)
            except Exception as e:  # noqa: BLE001
                db.rollback()
                LAST.update(at=utcnow(), ok=False, detail=f"{type(e).__name__}", summary=None)
                log.exception("detection pass failed")
            finally:
                db.close()

    threading.Thread(target=loop, name="ingest-stream", daemon=True).start()
