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

Per client: an admin may override the level of one skill for one client
(ClientPolicy) and the thresholds the rules use for that client (ClientThreshold).
autonomy() takes the client a proposal targets and falls back to the global level;
the high-risk ceiling applies to overrides too.
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


def _pid(client) -> str:
    if isinstance(client, dict):
        return str(client.get("id") or client.get("platform_client_id") or "")
    return str(client or "")


def client_override(db: Session, action: str, client) -> str | None:
    from .db import ClientPolicy

    pid = _pid(client)
    if not pid:
        return None
    row = db.execute(select(ClientPolicy).where(ClientPolicy.platform_client_id == pid,
                                                ClientPolicy.action == action)).scalar_one_or_none()
    return row.autonomy if row else None


def autonomy(db: Session, action: str, client=None) -> str:
    """The level for one skill, for one client when given (a platform client id or a
    client dict): the client's override when an admin set one, else the global row,
    else the skill's default. A high-risk skill is never automatic either way."""
    from .db import Policy

    s = skills.get(action)
    level = client_override(db, action, client)
    if level is None:
        row = db.get(Policy, action)
        level = row.autonomy if row else s.default
    # Hard ceiling: high-risk skills are never automatic.
    if s.risk == "high" and level == "auto":
        return "propose"
    return level


def set_client_autonomy(db: Session, pid: str, action: str, level: str, actor: str, client_name: str = "") -> str:
    from .db import ClientPolicy, utcnow

    if not pid or action not in skills.REGISTRY or level not in AUTONOMY:
        raise ValueError("bad client, action or level")
    if skills.get(action).risk == "high" and level == "auto":
        raise ValueError("a high-risk action cannot be automatic, for any client")
    row = db.execute(select(ClientPolicy).where(ClientPolicy.platform_client_id == pid,
                                                ClientPolicy.action == action)).scalar_one_or_none()
    if row is None:
        row = ClientPolicy(platform_client_id=pid, action=action)
        db.add(row)
    row.autonomy, row.client, row.updated_by, row.updated_at = level, client_name or row.client, actor, utcnow()
    db.commit()
    return level


def remove_client_autonomy(db: Session, override_id: str):
    from .db import ClientPolicy

    row = db.get(ClientPolicy, override_id)
    if row is None:
        return None
    gone = {"platform_client_id": row.platform_client_id, "client": row.client, "action": row.action, "autonomy": row.autonomy}
    db.delete(row)
    db.commit()
    return gone


def client_overrides(db: Session) -> list:
    from .db import ClientPolicy

    return db.execute(select(ClientPolicy).order_by(ClientPolicy.client, ClientPolicy.action)).scalars().all()


THRESHOLDS = ("escalate_after_minutes", "stale_case_days", "critical_ack_minutes")


def threshold(db: Session, client, name: str, default: int) -> int:
    """A per-client threshold when an admin set one, else the default given."""
    from .db import ClientThreshold

    pid = _pid(client)
    row = db.get(ClientThreshold, pid) if pid else None
    v = getattr(row, name, None) if row else None
    return int(v) if v is not None else default


def critical_ack(db: Session, client) -> tuple[int, str]:
    """(minutes, source) for acknowledging a critical: the client's override in
    SABINE, then the client's commitments on the platform, then the setting."""
    from .config import settings
    from .db import ClientThreshold

    pid = _pid(client)
    row = db.get(ClientThreshold, pid) if pid else None
    if row is not None and row.critical_ack_minutes is not None:
        return int(row.critical_ack_minutes), "client override"
    c = (client.get("commitments") or {}) if isinstance(client, dict) else {}
    try:
        if c.get("critical_ack_minutes") is not None:
            return int(c["critical_ack_minutes"]), f"{client.get('tier') or 'client'} commitment"
    except (TypeError, ValueError):
        pass
    return int(settings.critical_ack_minutes), "default"


def set_thresholds(db: Session, pid: str, values: dict, actor: str, client_name: str = ""):
    from .db import ClientThreshold, utcnow

    if not pid:
        raise ValueError("client required")
    clean: dict = {}
    for k in THRESHOLDS:
        v = values.get(k)
        if v in (None, ""):
            clean[k] = None
            continue
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{k} must be a whole number") from None
        if n < 1 or n > 100000:
            raise ValueError(f"{k} is out of range")
        clean[k] = n
    row = db.get(ClientThreshold, pid)
    if all(v is None for v in clean.values()):
        if row is not None:
            db.delete(row)
            db.commit()
        return None
    if row is None:
        row = ClientThreshold(platform_client_id=pid)
        db.add(row)
    for k, v in clean.items():
        setattr(row, k, v)
    row.client, row.updated_by, row.updated_at = client_name or row.client, actor, utcnow()
    db.commit()
    return row


def client_thresholds(db: Session) -> list:
    from .db import ClientThreshold

    return db.execute(select(ClientThreshold).order_by(ClientThreshold.client)).scalars().all()


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
