"""What SABINE is allowed to do on its own.

Every skill in the catalog (skills.py) carries a risk tier and a default autonomy
level. An admin sets the level per skill in the console:

- off: SABINE never raises this action.
- propose: SABINE writes the proposal and waits for a person to approve it.
- auto: SABINE carries it out as soon as the rule fires, and records that it did.

Hard limits that no setting changes: a skill with risk "high" can never be set to
auto, and anything that touches a client host (isolate, contain, quarantine) is
not an action SABINE can take at all. For those it raises a proposal whose
execution is a deep link into the module, where a person with the right grant
clicks, with the second-person control that module enforces.
"""
from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import skills

AUTONOMY = ("off", "propose", "auto")

# The catalog, in the shape older callers read: action -> dict(label, domain, risk,
# default, description, executor). skills.REGISTRY is the source.
ACTIONS = {s.key: {"label": s.title, "domain": s.domain, "risk": s.risk, "default": s.default,
                   "description": s.description, "executor": s.executor} for s in skills.REGISTRY.values()}

RISK_RANK = skills.RISK_RANK


def seed_policies(db: Session) -> None:
    from .db import Policy

    for s in skills.REGISTRY.values():
        if not db.get(Policy, s.key):
            db.add(Policy(action=s.key, autonomy=s.default))
    db.commit()


def autonomy(db: Session, action: str) -> str:
    from .db import Policy

    s = skills.get(action)
    row = db.get(Policy, action)
    level = row.autonomy if row else s.default
    # Hard ceiling: high-risk skills are never automatic.
    if s.risk == "high" and level == "auto":
        return "propose"
    return level


def set_autonomy(db: Session, action: str, level: str, actor: str) -> str:
    from .db import Policy, utcnow

    if action not in skills.REGISTRY or level not in AUTONOMY:
        raise ValueError("bad action or level")
    if skills.get(action).risk == "high" and level == "auto":
        raise ValueError("a high-risk action cannot be automatic")
    row = db.get(Policy, action)
    if row is None:
        row = Policy(action=action)
        db.add(row)
    row.autonomy, row.updated_by, row.updated_at = level, actor, utcnow()
    db.commit()
    return level


def last_runs(db: Session) -> dict[str, dict]:
    """When each skill was last carried out, from the ledger's action rows:
    {key: {at, ok, by}}. Action rows are summarised "<key> done: ..." or
    "<key> failed: ..." and carry the proposal's autonomy in their detail."""
    from .db import Ledger

    out: dict[str, dict] = {}
    rows = db.execute(select(Ledger).where(Ledger.kind == "action").order_by(desc(Ledger.chain_seq)).limit(2000)).scalars().all()
    for r in rows:
        key = (r.detail or {}).get("action") or r.summary.split(" ", 1)[0]
        if key in out or key not in skills.REGISTRY:
            continue
        out[key] = {"at": r.at, "ok": r.summary.split(":", 1)[0].endswith(" done"),
                    "by": (r.detail or {}).get("by") or ((r.detail or {}).get("autonomy") or "")}
        if len(out) == len(skills.REGISTRY):
            break
    return out


def table(db: Session) -> list[dict]:
    """The catalog with the live autonomy level and the last run per skill."""
    from .db import Policy

    runs = last_runs(db)
    out = []
    for s in skills.REGISTRY.values():
        row = db.get(Policy, s.key)
        last = runs.get(s.key)
        out.append({"action": s.key, **ACTIONS[s.key], **s.as_dict(),
                    "autonomy": row.autonomy if row else s.default,
                    "updated_by": row.updated_by if row else "",
                    "last_run": last["at"] if last else None,
                    "last_run_ok": last["ok"] if last else None,
                    "last_run_by": last["by"] if last else ""})
    return out


def catalog(db: Session) -> dict:
    """GET /api/skills: the catalog grouped by domain."""
    rows = {r["key"]: r for r in table(db)}
    groups = []
    for d, label, ss in skills.by_domain():
        groups.append({"domain": d, "label": label, "skills": [
            {**rows[s.key], "last_run": rows[s.key]["last_run"].isoformat() if rows[s.key]["last_run"] else None}
            for s in ss]})
    return {"domains": groups, "levels": list(AUTONOMY),
            "limits": ["a high-risk skill is never automatic", "SABINE never touches a client host"]}
