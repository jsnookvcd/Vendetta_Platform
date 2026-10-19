"""Proactive alerts: the problems a PM should hear about before the client does.

compute() reads the boards, milestones, change requests, notes and Harvest burn and
returns every live condition; sync() stores them by key, so a standing problem is
one alert from when it starts until it clears, notified once. A background loop
recomputes on an interval, posts new high-severity alerts to a Teams channel when a
webhook is set, and emails each person a morning digest of their open alerts when a
sender mailbox is set. SABINE reads the open set at GET /api/alerts and queues it.

Kinds: task_overdue, task_due_soon, task_blocked, wip_over, burn_warn, burn_over,
scope_creep, end_soon, end_overdue, phase_stale, milestone_overdue, change_pending,
publish_failed, note_mirror_failed.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import harvest
from .config import alert_settings as cfg
from .config import settings
from .db import (AuditLog, Board, BoardColumn, Card, CardEvent, ChangeRequest, Engagement, MeetingNote, Milestone,
                 Template, utcnow)

log = logging.getLogger(__name__)
TRANSPORT: httpx.BaseTransport | None = None
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
NY = ZoneInfo("America/New_York")


def _a(key, kind, severity, title, *, eng=None, card=None, owner="", detail="", link=""):
    return {"key": key, "kind": kind, "severity": severity, "title": title[:400], "detail": detail,
            "engagement_id": eng.id if eng else (card.engagement_id if card else None),
            "card_ref": card.ref if card else None, "owner": (owner or "").lower(),
            "link": link or (f"/tasks/{card.ref}" if card else f"/engagements/{eng.id}" if eng else "")}


def compute(db: Session, *, with_burn: bool = True) -> list[dict]:
    today = dt.date.today()
    now = utcnow()
    out: list[dict] = []
    engs = {e.id: e for e in db.execute(select(Engagement).where(Engagement.status != "closed")).scalars()}

    # ---- tasks
    rows = db.execute(select(Card, BoardColumn).join(BoardColumn, Card.column_id == BoardColumn.id)
                      .join(Board, Card.board_id == Board.id)
                      .where(Board.kind == "engagement", Card.archived.is_(False),
                             BoardColumn.is_done.is_(False))).all()
    soon = (now + dt.timedelta(hours=cfg.due_soon_hours)).date()
    for card, col in rows:
        eng = engs.get(card.engagement_id)
        if eng is None:
            continue
        owner = card.assignee or eng.pm_email
        label = f"#{card.ref} {card.title} ({eng.code})"
        if card.due_on and card.due_on < today:
            late = (today - card.due_on).days
            sev = "high" if card.priority in ("high", "urgent") or late > 3 else "medium"
            out.append(_a(f"task_overdue:{card.id}", "task_overdue", sev, f"Overdue {late}d: {label}", card=card,
                          owner=owner, detail=f"Due {card.due_on}, in {col.name}"))
        elif card.due_on and card.due_on <= soon:
            out.append(_a(f"task_due_soon:{card.id}", "task_due_soon", "low", f"Due {card.due_on}: {label}",
                          card=card, owner=owner))
        if col.name.lower() == "blocked":
            last = db.execute(select(CardEvent.at).where(CardEvent.card_id == card.id, CardEvent.kind.in_(
                ("moved", "created"))).order_by(CardEvent.at.desc()).limit(1)).scalar() or card.updated_at
            stuck = (now - last).days
            if stuck >= cfg.blocked_days:
                out.append(_a(f"task_blocked:{card.id}", "task_blocked", "medium", f"Blocked {stuck}d: {label}",
                              card=card, owner=eng.pm_email, detail="Unblock it, reassign it, or tell the client "
                                                                    "what you are waiting on"))

    # ---- WIP limits
    for col in db.execute(select(BoardColumn).where(BoardColumn.wip_limit.isnot(None))).scalars():
        n = db.query(Card).filter(Card.column_id == col.id, Card.archived.is_(False)).count()
        if col.wip_limit and n > col.wip_limit:
            b = db.get(Board, col.board_id)
            eng = engs.get(b.engagement_id) if b.engagement_id else None
            out.append(_a(f"wip_over:{col.id}", "wip_over", "medium",
                          f"{b.name}: '{col.name}' holds {n}, limit {col.wip_limit}", eng=eng,
                          owner=eng.pm_email if eng else "",
                          link=f"/engagements/{eng.id}" if eng else f"/boards/{b.practice}"))

    # ---- engagement dates and phases
    targets = {t.id: t.phase_days or {} for t in db.execute(select(Template)).scalars()}
    from .metrics import phase_days
    for eng in engs.values():
        if eng.status != "active":
            continue
        if eng.ends_on and eng.ends_on < today:
            out.append(_a(f"end_overdue:{eng.id}", "end_overdue", "high",
                          f"{eng.code} is past its planned end ({eng.ends_on})", eng=eng, owner=eng.pm_email,
                          detail="Close it, or raise a change request for the new date"))
        elif eng.ends_on and eng.ends_on <= today + dt.timedelta(days=cfg.end_soon_days):
            out.append(_a(f"end_soon:{eng.id}", "end_soon", "low", f"{eng.code} ends {eng.ends_on}", eng=eng,
                          owner=eng.pm_email))
        tgt = targets.get(eng.template_id) or {}
        if tgt:
            spent = phase_days(db, eng)
            from .service import practice_card
            card = practice_card(db, eng)
            phase = card.column.name if card else None
            if phase and phase in tgt and spent.get(phase, 0) > tgt[phase]:
                out.append(_a(f"phase_stale:{eng.id}:{phase}", "phase_stale", "medium",
                              f"{eng.code} has been in {phase} {spent[phase]:.0f}d (target {tgt[phase]}d)",
                              eng=eng, owner=eng.pm_email))
        if eng.publish_status == "failed":
            out.append(_a(f"publish_failed:{eng.id}", "publish_failed", "medium",
                          f"{eng.code}: milestones did not reach the client portal", eng=eng, owner=eng.pm_email,
                          detail=eng.publish_detail))

    # ---- milestones
    for m in db.execute(select(Milestone).where(Milestone.status != "done", Milestone.due_on.isnot(None),
                                                Milestone.due_on < today)).scalars():
        eng = engs.get(m.engagement_id)
        if eng:
            out.append(_a(f"milestone_overdue:{m.id}", "milestone_overdue", "high" if m.client_visible else "medium",
                          f"Milestone overdue: {m.title} ({eng.code}, due {m.due_on})", eng=eng, owner=eng.pm_email,
                          detail="The client can see this milestone" if m.client_visible else ""))

    # ---- change requests
    for cr in db.execute(select(ChangeRequest).where(ChangeRequest.status == "requested")).scalars():
        waited = (now - cr.requested_at).days
        eng = engs.get(cr.engagement_id)
        if eng and waited >= cfg.change_pending_days:
            owner = eng.pm_email if eng.pm_email != cr.requested_by else ""
            out.append(_a(f"change_pending:{cr.id}", "change_pending", "medium",
                          f"CR-{cr.number} on {eng.code} waiting {waited}d for a decision: {cr.title}", eng=eng,
                          owner=owner, link=f"/engagements/{eng.id}#changes"))

    # ---- notes that did not reach SharePoint
    for n in db.execute(select(MeetingNote).where(MeetingNote.sp_status == "failed")).scalars():
        out.append(_a(f"note_mirror_failed:{n.id}", "note_mirror_failed", "low",
                      f"Meeting note not in SharePoint: {n.title}", eng=n.engagement, owner=n.author,
                      detail=n.sp_error, link=f"/notes/{n.id}"))

    # ---- budget burn and scope creep
    if with_burn and harvest.configured():
        linked = [e for e in engs.values() if e.harvest_project_id and e.budget_hours]
        if linked:
            start = max(min(e.starts_on or e.created_at.date() for e in linked), today - dt.timedelta(days=364))
            try:
                hours = harvest.project_hours_report(start, today)
            except harvest.HarvestError as e:
                log.warning("alerts: burn skipped: %s", e)
                hours = {}
            for eng in linked:
                h = hours.get(eng.harvest_project_id)
                if h is None:
                    continue
                pct = 100 * h / eng.budget_hours
                if pct >= cfg.burn_over_pct:
                    out.append(_a(f"burn_over:{eng.id}", "burn_over", "high",
                                  f"{eng.code} is over budget: {h:.1f}h of {eng.budget_hours:g}h ({pct:.0f}%)",
                                  eng=eng, owner=eng.pm_email))
                elif pct >= cfg.burn_warn_pct:
                    out.append(_a(f"burn_warn:{eng.id}", "burn_warn", "medium",
                                  f"{eng.code} has used {pct:.0f}% of its budget ({h:.1f}h of {eng.budget_hours:g}h)",
                                  eng=eng, owner=eng.pm_email))
                base = eng.baseline_budget_hours
                any_cr = db.query(ChangeRequest).filter(ChangeRequest.engagement_id == eng.id).count()
                if base and h > base and not any_cr:
                    out.append(_a(f"scope_creep:{eng.id}", "scope_creep", "high",
                                  f"{eng.code} is past its sold hours ({h:.1f}h of {base:g}h) with no change request",
                                  eng=eng, owner=eng.pm_email,
                                  detail="Raise a change request with the client before more time goes unbilled",
                                  link=f"/engagements/{eng.id}#changes"))
    return out


def sync(db: Session, *, with_burn: bool = True) -> dict:
    """Store the current conditions. Returns {"new": [...], "resolved": n, "open": n}."""
    now = utcnow()
    live = {a["key"]: a for a in compute(db, with_burn=with_burn)}
    from .db import Alert
    existing = {a.key: a for a in db.execute(select(Alert)).scalars()}
    new = []
    for key, a in live.items():
        row = existing.get(key)
        if row is None or row.resolved_at is not None:
            if row is None:
                row = Alert(key=key)
                db.add(row)
            row.first_seen, row.resolved_at, row.notified_at, row.acked_by, row.acked_at = now, None, None, "", None
            new.append(a)
        for f in ("kind", "severity", "engagement_id", "card_ref", "owner", "title", "detail", "link"):
            setattr(row, f, a[f])
        row.last_seen = now
    resolved = 0
    for key, row in existing.items():
        if key not in live and row.resolved_at is None:
            row.resolved_at = now
            resolved += 1
    db.flush()
    return {"new": new, "resolved": resolved, "open": len(live)}


def alert_dict(a) -> dict:
    return {"key": a.key, "kind": a.kind, "severity": a.severity, "title": a.title, "detail": a.detail,
            "engagement_id": a.engagement_id, "card_ref": a.card_ref, "owner": a.owner or None, "link": a.link,
            "first_seen": a.first_seen.isoformat(), "acked_by": a.acked_by or None,
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None}


def open_alerts(db: Session, *, owner: str | None = None, severity: str | None = None,
                engagement_id: str | None = None, include_acked: bool = True) -> list:
    from .db import Alert
    q = select(Alert).where(Alert.resolved_at.is_(None))
    if owner:
        q = q.where(Alert.owner == owner.lower())
    if severity:
        q = q.where(Alert.severity == severity)
    if engagement_id:
        q = q.where(Alert.engagement_id == engagement_id)
    if not include_acked:
        q = q.where(Alert.acked_by == "")
    rows = list(db.execute(q).scalars())
    rows.sort(key=lambda a: (SEV_ORDER.get(a.severity, 9), a.first_seen))
    return rows


def ack(db: Session, actor: str, key: str):
    from .db import Alert
    from .service import ServiceError
    row = db.get(Alert, key)
    if row is None or row.resolved_at is not None:
        raise ServiceError("That alert is not open", 404)
    row.acked_by, row.acked_at = actor, utcnow()
    db.flush()
    return row


# ---------------------------------------------------------------- delivery
def _public(link: str) -> str:
    return f"{settings.public_url.rstrip('/')}{link}" if settings.public_url and link.startswith("/") else link


def post_teams(alerts: list[dict]) -> bool:
    if not cfg.teams_webhook_url or not alerts:
        return False
    lines = [f"- [{a['severity'].upper()}] {a['title']}" + (f" ({a['owner']})" if a["owner"] else "")
             for a in alerts[:15]]
    card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
        "body": [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                  "text": f"Project Management: {len(alerts)} new alert(s)"},
                 {"type": "TextBlock", "wrap": True, "text": "\n".join(lines)}],
        "actions": [{"type": "Action.OpenUrl", "title": "Open alerts", "url": _public("/alerts")}]
        if settings.public_url else []}}]}
    try:
        with httpx.Client(timeout=20, transport=TRANSPORT) as http:
            http.post(cfg.teams_webhook_url, json=card).raise_for_status()
        return True
    except Exception as e:  # noqa: BLE001
        log.error("teams alert post failed: %s", e)
        return False


def send_digests(db: Session) -> dict:
    """Email each owner their open alerts through Microsoft Graph (sendMail from
    ALERT_MAIL_FROM, which needs the Mail.Send application permission)."""
    if not cfg.mail_from:
        return {"sent": 0, "reason": "ALERT_MAIL_FROM not set"}
    from . import sharepoint
    by_owner: dict[str, list] = {}
    for a in open_alerts(db):
        if a.owner and "@" in a.owner:
            by_owner.setdefault(a.owner, []).append(a)
    sent = 0
    with httpx.Client(timeout=20.0, transport=sharepoint.TRANSPORT) as http:
        try:
            token = sharepoint._token(http)
        except Exception as e:  # noqa: BLE001
            log.error("digest: no Graph token: %s", e)
            return {"sent": 0, "reason": str(e)}
        for owner, rows in by_owner.items():
            items = "".join(f"<li><b>{a.severity.upper()}</b> <a href=\"{_public(a.link)}\">{a.title}</a>"
                            f"{(' - ' + a.detail) if a.detail else ''}</li>" for a in rows)
            msg = {"message": {"subject": f"Your delivery alerts: {len(rows)} open",
                               "body": {"contentType": "HTML", "content": f"<p>Open alerts on your engagements and "
                                        f"tasks:</p><ul>{items}</ul>"},
                               "toRecipients": [{"emailAddress": {"address": owner}}]}, "saveToSentItems": False}
            r = http.post(f"https://graph.microsoft.com/v1.0/users/{cfg.mail_from}/sendMail", json=msg,
                          headers={"Authorization": f"Bearer {token}"})
            if r.status_code in (200, 202):
                sent += 1
            else:
                log.warning("digest to %s failed: HTTP %s", owner, r.status_code)
    return {"sent": sent, "owners": len(by_owner)}


def run_once(db: Session, *, with_burn: bool = True) -> dict:
    res = sync(db, with_burn=with_burn)
    high = [a for a in res["new"] if a["severity"] == "high"]
    if high and post_teams(high):
        from .db import Alert
        for a in high:
            row = db.get(Alert, a["key"])
            if row:
                row.notified_at = utcnow()
    db.commit()
    return {"new": len(res["new"]), "new_high": len(high), "resolved": res["resolved"], "open": res["open"]}


def start_loop(session_factory) -> None:
    if cfg.interval_seconds <= 0:
        return

    def _loop():
        time.sleep(20)
        while True:
            db = session_factory()
            try:
                log.info("alerts: %s", run_once(db))
                now_ny = dt.datetime.now(NY)
                if cfg.digest_hour_local >= 0 and now_ny.hour == cfg.digest_hour_local and cfg.mail_from:
                    tag = f"digest {now_ny.date().isoformat()}"
                    if not db.query(AuditLog).filter(AuditLog.action == "alerts.digest",
                                                     AuditLog.detail.like(f"{tag}%")).first():
                        res = send_digests(db)
                        db.add(AuditLog(actor="system", action="alerts.digest", detail=f"{tag} {res}"))
                        db.commit()
            except Exception as e:  # noqa: BLE001
                db.rollback()
                log.warning("alerts loop: %s", e)
            finally:
                db.close()
            time.sleep(cfg.interval_seconds)

    threading.Thread(target=_loop, name="pm-alerts", daemon=True).start()
