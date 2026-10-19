"""Capacity planning: who is overloaded, who can take the next case.

Load comes from the task boards. Each open task assigned to a person contributes its
remaining estimate (its estimate less the share of its checklist already done) to
the week it is due; overdue work lands in the current week, and work with no due
date is reported as unscheduled. A task with no estimate counts at DEFAULT_ESTIMATE
hours and is flagged, so the gap is visible and PMs are nudged to estimate.

Capacity per person is their bookable hours per week: set here, else their Harvest
weekly capacity, else DEFAULT_WEEKLY. The current week's Harvest actuals sit beside
the plan.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import harvest
from .db import Board, BoardColumn, Capacity, Card, Engagement, User, utcnow

DEFAULT_ESTIMATE = 2.0
DEFAULT_WEEKLY = 32.0


def _monday(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())


def _remaining(card: Card) -> tuple[float, bool]:
    est = card.estimate_hours
    flagged = est is None
    est = DEFAULT_ESTIMATE if est is None else float(est)
    items = card.checklist or []
    if items:
        done = sum(1 for i in items if i.get("done"))
        est = est * (1 - done / len(items))
    return round(est, 2), flagged


def set_capacity(db: Session, email: str, *, weekly_hours=None, practices: str | None = None,
                 active: bool | None = None, name: str | None = None) -> Capacity:
    from .service import ServiceError

    email = (email or "").strip().lower()
    if "@" not in email:
        raise ServiceError("Give the person's email")
    row = db.get(Capacity, email) or Capacity(email=email)
    if weekly_hours is not None:
        h = float(weekly_hours)
        if not 0 <= h <= 80:
            raise ServiceError("Weekly hours must be between 0 and 80")
        row.weekly_hours = h
    if practices is not None:
        row.practices = practices
    if active is not None:
        row.active = bool(active)
    if name is not None:
        row.name = name
    row.updated_at = utcnow()
    db.add(row)
    db.flush()
    return row


def team(db: Session, *, weeks: int = 4, practice: str | None = None, with_actuals: bool = True) -> dict:
    weeks = max(1, min(int(weeks or 4), 12))
    today = dt.date.today()
    start = _monday(today)
    starts = [start + dt.timedelta(weeks=i) for i in range(weeks)]
    end = starts[-1] + dt.timedelta(days=6)

    q = (select(Card, Board.practice).join(Board, Card.board_id == Board.id)
         .join(BoardColumn, Card.column_id == BoardColumn.id)
         .where(Board.kind == "engagement", Card.archived.is_(False), BoardColumn.is_done.is_(False),
                Card.assignee != ""))
    if practice:
        q = q.where(Board.practice == practice)
    cards = db.execute(q).all()

    people: dict[str, dict] = {}

    def person(email: str) -> dict:
        if email not in people:
            people[email] = {"email": email, "weeks": [0.0] * weeks, "beyond": 0.0, "unscheduled": 0.0,
                             "unestimated_tasks": 0, "open_tasks": 0, "overdue_tasks": 0}
        return people[email]

    for card, _p in cards:
        p = person(card.assignee.lower())
        hrs, flagged = _remaining(card)
        p["open_tasks"] += 1
        p["unestimated_tasks"] += int(flagged)
        if card.due_on is None:
            p["unscheduled"] += hrs
            continue
        if card.due_on < today:
            p["overdue_tasks"] += 1
        idx = max(0, (_monday(card.due_on) - start).days // 7)
        if idx < weeks:
            p["weeks"][idx] += hrs
        else:
            p["beyond"] += hrs

    caps = {c.email: c for c in db.execute(select(Capacity)).scalars()}
    for email, c in caps.items():
        if c.active and (not practice or practice in (c.practices or "")):
            person(email)
    for u in db.execute(select(User).where(User.active.is_(True), User.role.in_(("analyst", "admin")))).scalars():
        if "@" in u.email and (not practice or u.email in people):
            person(u.email.lower())

    hv_caps, actual, hv_error = {}, {}, None
    if with_actuals and harvest.configured():
        try:
            hv_caps = harvest.weekly_capacity()
            actual = harvest.team_hours(start, today)
        except harvest.HarvestError as e:
            hv_error = str(e)

    pm_of = {}
    for e in db.execute(select(Engagement).where(Engagement.status != "closed")).scalars():
        pm_of[e.pm_email] = pm_of.get(e.pm_email, 0) + 1

    rows = []
    for email, p in people.items():
        if "@" not in email:
            continue  # the break-glass admin login is not a person to plan against
        c = caps.get(email)
        if c is not None and not c.active:
            continue
        cap = c.weekly_hours if c else hv_caps.get(email) or DEFAULT_WEEKLY
        weeks_out = []
        for i, w in enumerate(starts):
            planned = round(p["weeks"][i], 1)
            weeks_out.append({"week_of": w.isoformat(), "planned_hours": planned, "capacity_hours": cap,
                              "load_pct": round(100 * planned / cap) if cap else None,
                              "over": bool(cap and planned > cap)})
        free2 = round(sum(max(0.0, cap - x["planned_hours"]) for x in weeks_out[:2]), 1)
        rows.append({"email": email, "name": c.name if c and c.name else "", "capacity_hours": cap,
                     "weeks": weeks_out, "unscheduled_hours": round(p["unscheduled"], 1),
                     "later_hours": round(p["beyond"], 1), "open_tasks": p["open_tasks"],
                     "overdue_tasks": p["overdue_tasks"], "unestimated_tasks": p["unestimated_tasks"],
                     "engagements_as_pm": pm_of.get(email, 0), "free_hours_next_2_weeks": free2,
                     "harvest_hours_this_week": actual.get(email)})
    rows.sort(key=lambda r: -max((w["load_pct"] or 0) for w in r["weeks"]))
    over = [r["email"] for r in rows if any(w["over"] for w in r["weeks"][:2])]
    best = sorted(rows, key=lambda r: -r["free_hours_next_2_weeks"])[:3]
    return {"weeks": [w.isoformat() for w in starts], "through": end.isoformat(), "people": rows,
            "overloaded_next_2_weeks": over,
            "most_available": [{"email": r["email"], "free_hours_next_2_weeks": r["free_hours_next_2_weeks"]}
                               for r in best],
            "assumptions": f"Unestimated tasks count as {DEFAULT_ESTIMATE}h; capacity defaults to "
                           f"{DEFAULT_WEEKLY}h/week when not set here or in Harvest.",
            "harvest_error": hv_error}


def can_take(db: Session, *, practice: str, hours: float, weeks: int = 2) -> dict:
    """Can the team absorb a new engagement of about `hours` over the next `weeks`?"""
    t = team(db, weeks=max(weeks, 1), practice=practice, with_actuals=False)
    free = []
    for r in t["people"]:
        f = round(sum(max(0.0, w["capacity_hours"] - w["planned_hours"]) for w in r["weeks"][:weeks]), 1)
        free.append({"email": r["email"], "free_hours": f})
    free.sort(key=lambda x: -x["free_hours"])
    total = round(sum(x["free_hours"] for x in free), 1)
    return {"practice": practice, "hours_needed": hours, "weeks": weeks, "team_free_hours": total,
            "fits": total >= hours, "best_placed": free[:3],
            "note": "Free hours are capacity less planned task estimates; unestimated tasks count at "
                    f"{DEFAULT_ESTIMATE}h each."}
