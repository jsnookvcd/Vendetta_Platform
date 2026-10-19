"""Portfolio metrics across engagements.

Built from what the boards already record:
  - key dates on each engagement (opened, contained, report delivered, closed), set
    when its practice card first enters the marking columns or by hand;
  - every move of a practice card (card_events), which gives days spent per phase;
  - due dates against completion for tasks and milestones;
  - the baseline against approved change requests for scope growth;
  - Harvest hours per project against each engagement's budget.

Grouped by practice and by engagement type (the template it opened from), over a
window of recent engagements. This is the record that lets Vendetta price, staff
and promise from its own history.
"""
from __future__ import annotations

import datetime as dt
import re
import statistics

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import harvest
from .db import (Board, BoardColumn, Card, CardEvent, ChangeRequest, Engagement, Milestone, Template, utcnow)

_MOVE = re.compile(r"^(.*?) -> (.*?)(?: \(.*\))?$")


def _med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 1) if xs else None


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def _pct(n, d):
    return round(100 * n / d) if d else None


def phase_days(db: Session, eng: Engagement) -> dict[str, float]:
    """Days the engagement's practice card spent in each column, from its moves."""
    pboard = db.execute(select(Board).where(Board.kind == "practice", Board.practice == eng.practice)).scalar_one()
    card = db.execute(select(Card).where(Card.board_id == pboard.id, Card.engagement_id == eng.id)).scalars().first()
    if card is None:
        return {}
    events = db.execute(select(CardEvent).where(CardEvent.card_id == card.id, CardEvent.kind.in_(("created", "moved")))
                        .order_by(CardEvent.at, CardEvent.id)).scalars().all()
    stays: list[tuple[str, dt.datetime]] = []
    for e in events:
        if e.kind == "created":
            m = re.search(r"opened in (.+)$", e.detail or "")
            if m:
                stays.append((m.group(1), e.at))
        else:
            m = _MOVE.match(e.detail or "")
            if m:
                if not stays:
                    stays.append((m.group(1), eng.created_at))
                stays.append((m.group(2), e.at))
    out: dict[str, float] = {}
    end = eng.closed_at or utcnow()
    for i, (col, at) in enumerate(stays):
        nxt = stays[i + 1][1] if i + 1 < len(stays) else end
        if i + 1 == len(stays) and eng.status == "closed":
            continue  # the closed column itself is not a phase
        out[col] = round(out.get(col, 0) + max(0.0, (nxt - at).total_seconds() / 86400), 2)
    return out


def engagement_metrics(db: Session, eng: Engagement, hours: float | None = None) -> dict:
    opened = eng.created_at
    days = lambda a, b: round((b - a).total_seconds() / 86400, 1) if a and b else None  # noqa: E731
    crs = db.execute(select(ChangeRequest).where(ChangeRequest.engagement_id == eng.id)).scalars().all()
    approved = [c for c in crs if c.status == "approved"]
    ms = db.execute(select(Milestone).where(Milestone.engagement_id == eng.id)).scalars().all()
    ms_due_done = [m for m in ms if m.due_on and m.completed_at]
    board = db.execute(select(Board).where(Board.engagement_id == eng.id)).scalar_one_or_none()
    tasks = []
    if board:
        tasks = db.execute(select(Card).join(BoardColumn, Card.column_id == BoardColumn.id).where(
            Card.board_id == board.id, BoardColumn.is_done.is_(True), Card.due_on.isnot(None),
            Card.completed_at.isnot(None))).scalars().all()
    closed_on = eng.closed_at.date() if eng.closed_at else None
    out = {
        "code": eng.code, "name": eng.name, "practice": eng.practice, "type": eng.engagement_type or "untyped",
        "status": eng.status, "client": eng.client_name,
        "time_to_contain_hours": round((eng.contained_at - opened).total_seconds() / 3600, 1)
        if eng.contained_at else None,
        "time_to_report_days": days(opened, eng.reported_at),
        "cycle_days": days(opened, eng.closed_at),
        "on_time": (closed_on <= eng.ends_on) if closed_on and eng.ends_on else None,
        "on_time_vs_baseline": (closed_on <= eng.baseline_ends_on) if closed_on and eng.baseline_ends_on else None,
        "baseline_hours": eng.baseline_budget_hours, "budget_hours": eng.budget_hours,
        "scope_growth_hours": round(sum(c.hours_delta for c in approved), 1),
        "change_requests": len(crs),
        "milestones_on_time": sum(1 for m in ms_due_done if m.completed_at.date() <= m.due_on),
        "milestones_due_and_done": len(ms_due_done),
        "tasks_on_time": sum(1 for t in tasks if t.completed_at.date() <= t.due_on),
        "tasks_due_and_done": len(tasks),
        "phase_days": phase_days(db, eng),
    }
    if hours is not None:
        out["hours"] = hours
        if eng.budget_hours:
            out["budget_variance_pct"] = round(100 * (hours - eng.budget_hours) / eng.budget_hours, 1)
        if eng.baseline_budget_hours:
            out["baseline_variance_pct"] = round(100 * (hours - eng.baseline_budget_hours) / eng.baseline_budget_hours, 1)
    return out


def _group(rows: list[dict], targets: dict[str, dict]) -> dict:
    closed = [r for r in rows if r["status"] == "closed"]
    phases: dict[str, list[float]] = {}
    for r in rows:
        for col, d in r["phase_days"].items():
            phases.setdefault(col, []).append(d)
    tgt = {}
    for t in targets.values():
        for k, v in (t or {}).items():
            tgt.setdefault(k, v)
    on_time = [r["on_time"] for r in closed if r["on_time"] is not None]
    return {
        "engagements": len(rows), "closed": len(closed),
        "median_time_to_contain_hours": _med([r["time_to_contain_hours"] for r in rows]),
        "median_time_to_report_days": _med([r["time_to_report_days"] for r in rows]),
        "median_cycle_days": _med([r["cycle_days"] for r in closed]),
        "on_time_close_pct": _pct(sum(1 for x in on_time if x), len(on_time)),
        "avg_budget_variance_pct": _avg([r.get("budget_variance_pct") for r in rows]),
        "avg_baseline_variance_pct": _avg([r.get("baseline_variance_pct") for r in rows]),
        "scope_growth_hours": round(sum(r["scope_growth_hours"] for r in rows), 1),
        "change_requests": sum(r["change_requests"] for r in rows),
        "milestones_on_time_pct": _pct(sum(r["milestones_on_time"] for r in rows),
                                       sum(r["milestones_due_and_done"] for r in rows)),
        "tasks_on_time_pct": _pct(sum(r["tasks_on_time"] for r in rows), sum(r["tasks_due_and_done"] for r in rows)),
        "avg_days_per_phase": {k: {"avg": _avg(v), "target": tgt.get(k)} for k, v in phases.items()},
    }


def portfolio(db: Session, *, days: int = 90, practice: str | None = None, engagement_type: str | None = None,
              with_hours: bool = True) -> dict:
    since = utcnow() - dt.timedelta(days=max(1, int(days)))
    q = select(Engagement).where(or_(Engagement.created_at >= since, Engagement.closed_at >= since,
                                     Engagement.status != "closed"))
    if practice:
        q = q.where(Engagement.practice == practice)
    if engagement_type:
        q = q.where(Engagement.engagement_type == engagement_type)
    engs = list(db.execute(q).scalars())

    hours_by_project, hours_error = {}, None
    linked = [e for e in engs if e.harvest_project_id]
    if with_hours and linked and harvest.configured():
        start = max(min(e.starts_on or e.created_at.date() for e in linked),
                    dt.date.today() - dt.timedelta(days=364))
        try:
            hours_by_project = harvest.project_hours_report(start, dt.date.today())
        except harvest.HarvestError as e:
            hours_error = str(e)

    rows = [engagement_metrics(db, e, hours_by_project.get(e.harvest_project_id) if e.harvest_project_id
                               and hours_by_project else None) for e in engs]
    targets = {t.key: t.phase_days for t in db.execute(select(Template)).scalars()}
    by_practice = {p: _group([r for r in rows if r["practice"] == p], targets)
                   for p in sorted({r["practice"] for r in rows})}
    by_type = {k: _group([r for r in rows if r["type"] == k], {k: targets.get(k)})
               for k in sorted({r["type"] for r in rows})}
    return {"window_days": days, "since": since.date().isoformat(), "totals": _group(rows, targets),
            "by_practice": by_practice, "by_type": by_type, "engagements": rows, "harvest_error": hours_error}
