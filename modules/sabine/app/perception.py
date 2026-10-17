"""Perception: SABINE looks at every module through the same APIs an operator
would use and keeps one consistent picture (Snapshot per source) plus the operator
queue (WorkItem), the list of everything across the platform that is waiting on a
person or on SABINE.

Nothing here decides anything. It records what is true now, marks what was true
last time and is no longer observed as gone, and leaves reasoning to reasoner.py.
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import reach
from .config import settings
from .db import Snapshot, WorkItem, utcnow

log = logging.getLogger(__name__)

FINDING_MODULES = ["dark-web-monitoring", "managed-services", "vulnerability-management", "penetration-testing"]
# Where a person opens a finding in each module, by the finding id.
FINDING_PATH = {
    "dark-web-monitoring": "/hits/{id}",
    "managed-services": "/alerts/{id}",
    "vulnerability-management": "/findings/{id}",
    "penetration-testing": "/findings/{id}",
}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# The Office of Special Projects serves engagements, not findings.
SERVICES_MODULES = ["professional-services"]


def _snap(db: Session, source: str, res: dict) -> None:
    row = db.get(Snapshot, source)
    if row is None:
        row = Snapshot(source=source)
        db.add(row)
    row.ok = bool(res["ok"])
    row.detail = res["detail"][:300]
    if res["ok"]:
        row.payload = res["data"] if isinstance(res["data"], (dict, list)) else {}
    row.at = utcnow()


def observe(db: Session) -> dict:
    """Refresh every snapshot. Returns {source: ok} so the cycle can say what it saw."""
    seen: dict[str, bool] = {}
    d = reach.directory()
    if "platform" in d:
        for name, path, params in (("clients", "/api/platform/clients", None),
                                   ("staff", "/api/platform/staff", None),
                                   ("readiness", "/api/platform/readiness", None),
                                   ("modules", "/api/platform/modules", None)):
            res = reach.get("platform", path, params=params, timeout=30.0)
            _snap(db, f"platform:{name}", res)
            seen[f"platform:{name}"] = res["ok"]
    for key in d:
        if key == "platform":
            continue
        res = reach.get(key, "/api/module", timeout=10.0)
        _snap(db, f"module:{key}", res)
        seen[f"module:{key}"] = res["ok"]
        if key in FINDING_MODULES:
            res = reach.get(key, "/api/findings", params={"status": "active"}, timeout=20.0)
            _snap(db, f"findings:{key}", res)
            seen[f"findings:{key}"] = res["ok"]
        if key == "incident-response":
            res = reach.get(key, "/api/ir-cases", params={"status": "active"}, timeout=20.0)
            _snap(db, f"cases:{key}", res)
            seen[f"cases:{key}"] = res["ok"]
        if key in SERVICES_MODULES:
            res = reach.get(key, "/api/engagements", params={"status": "open"}, timeout=20.0)
            _snap(db, f"engagements:{key}", res)
            seen[f"engagements:{key}"] = res["ok"]
    db.commit()
    return seen


def snapshot(db: Session, source: str):
    row = db.get(Snapshot, source)
    return row.payload if row and row.ok else None


def snapshots(db: Session) -> dict[str, Snapshot]:
    return {s.source: s for s in db.execute(select(Snapshot)).scalars().all()}


def findings(db: Session) -> list[dict]:
    out = []
    for key in FINDING_MODULES:
        rows = snapshot(db, f"findings:{key}")
        for f in (rows if isinstance(rows, list) else []):
            f = dict(f)
            f["_module"] = key
            out.append(f)
    return out


def cases(db: Session) -> list[dict]:
    rows = snapshot(db, "cases:incident-response")
    return list(rows) if isinstance(rows, list) else []


def engagements(db: Session) -> list[dict]:
    """Open professional-services engagements with their deliverables."""
    out = []
    for key in SERVICES_MODULES:
        rows = snapshot(db, f"engagements:{key}")
        for e in (rows if isinstance(rows, list) else []):
            e = dict(e)
            e["_module"] = key
            out.append(e)
    return out


def clients(db: Session) -> list[dict]:
    p = snapshot(db, "platform:clients")
    return list((p or {}).get("clients") or []) if isinstance(p, dict) else []


def staff(db: Session) -> dict:
    p = snapshot(db, "platform:staff")
    return p if isinstance(p, dict) else {"governs": None, "staff": []}


def readiness(db: Session) -> dict:
    p = snapshot(db, "platform:readiness")
    return p if isinstance(p, dict) else {}


def module_manifest(db: Session, key: str) -> dict:
    p = snapshot(db, f"module:{key}")
    return p if isinstance(p, dict) else {}


def _upsert(db: Session, key: str, **vals) -> WorkItem:
    w = db.execute(select(WorkItem).where(WorkItem.key == key)).scalar_one_or_none()
    now = utcnow()
    if w is None:
        w = WorkItem(key=key, first_seen=now, **vals)
        db.add(w)
    else:
        for k, v in vals.items():
            if k in ("owner", "state") and getattr(w, k) not in ("open", ""):
                continue  # a claim or a close by a person is not overwritten by observation
            setattr(w, k, v)
        if w.state == "gone":
            w.state = "open"  # it came back
    w.last_seen = now
    return w


def build_queue(db: Session) -> dict:
    """Turn the snapshots into the operator queue. Items observed this pass are
    upserted; items from earlier passes that were not observed are marked gone."""
    now = utcnow()
    observed: set[str] = set()
    counts = {"finding": 0, "case": 0, "readiness": 0, "services": 0}

    for f in findings(db):
        sev = f.get("severity", "medium")
        if SEV_RANK.get(sev, 1) < SEV_RANK["high"]:
            continue
        mod = f["_module"]
        subj = f.get("subject") or {}
        key = f"finding:{mod}:{f['id']}"
        link = reach.public_url(mod) + FINDING_PATH[mod].format(id=f["id"]) if reach.public_url(mod) else ""
        _upsert(db, key, source=mod, kind="finding", domain="soc", title=f"{sev}: {f.get('title', '')}"[:400],
                client=subj.get("client", ""), platform_client_id=subj.get("platform_client_id") or "",
                severity=sev, link=link,
                payload={"finding": {k: f.get(k) for k in ("id", "type", "status", "title", "matched", "created_at", "workstream")},
                         "case_ref": subj.get("case_ref") or "", "copilot": f.get("copilot")})
        observed.add(key)
        counts["finding"] += 1

    for c in cases(db):
        key = f"case:incident-response:{c['id']}"
        pub = reach.public_url("incident-response")
        link = f"{pub}/cases/{c['id']}" if pub else ""
        _upsert(db, key, source="incident-response", kind="case", domain="soc",
                title=f"{c.get('number', '')}: {c.get('title', '')}"[:400],
                client=(c.get("client") or {}).get("name", ""),
                platform_client_id=(c.get("client") or {}).get("platform_client_id") or "",
                severity=c.get("severity", "high"), link=link,
                payload={"case": {k: c.get(k) for k in ("number", "status", "lead", "opened_at", "source_module", "origin")},
                         "board": c.get("board") or {}, "workstreams": c.get("workstreams") or []})
        observed.add(key)
        counts["case"] += 1

    rep = readiness(db)
    pub = reach.public_url("platform")
    for mod in rep.get("modules") or []:
        for chk in mod.get("checks") or []:
            if chk.get("state") != "fail":
                continue
            key = f"readiness:{mod['key']}:{chk['label']}"
            _upsert(db, key, source="platform", kind="readiness", domain="admin",
                    title=f"{mod['display_name']}: {chk['label']}"[:400], severity="high",
                    link=f"{pub}/readiness" if pub else "", payload={"check": chk, "module": mod["key"]})
            observed.add(key)
            counts["readiness"] += 1
    for chk in (rep.get("control_plane") or {}).get("checks") or []:
        if chk.get("state") == "fail":
            key = f"readiness:platform:{chk['label']}"
            _upsert(db, key, source="platform", kind="readiness", domain="admin",
                    title=f"Control plane: {chk['label']}"[:400], severity="high",
                    link=f"{pub}/readiness" if pub else "", payload={"check": chk, "module": "platform"})
            observed.add(key)
            counts["readiness"] += 1

    # Services: retests waiting and remediation past SLA come from the finding snapshots.
    for f in findings(db):
        mod, status = f["_module"], f.get("status")
        subj = f.get("subject") or {}
        if mod == "penetration-testing" and f.get("native_status") == "retest_pending":
            key = f"retest:{mod}:{f['id']}"
            link = reach.public_url(mod) + FINDING_PATH[mod].format(id=f["id"]) if reach.public_url(mod) else ""
            _upsert(db, key, source=mod, kind="retest", domain="services", title=f"Retest waiting: {f.get('title', '')}"[:400],
                    client=subj.get("client", ""), platform_client_id=subj.get("platform_client_id") or "",
                    severity=f.get("severity", "medium"), link=link, payload={"finding_id": f["id"]})
            observed.add(key)
            counts["services"] += 1
        if mod == "vulnerability-management" and f.get("native_status") == "remediating":
            created = f.get("created_at")
            try:
                age = (now - dt.datetime.fromisoformat(created)).days if created else 0
            except ValueError:
                age = 0
            sla = settings.remediation_sla_days.get(f.get("severity", "medium"), 90)
            if age > sla:
                key = f"overdue:{mod}:{f['id']}"
                link = reach.public_url(mod) + FINDING_PATH[mod].format(id=f["id"]) if reach.public_url(mod) else ""
                _upsert(db, key, source=mod, kind="overdue", domain="services",
                        title=f"Remediation {age - sla}d past SLA: {f.get('title', '')}"[:400],
                        client=subj.get("client", ""), platform_client_id=subj.get("platform_client_id") or "",
                        severity=f.get("severity", "medium"), link=link,
                        due_at=now - dt.timedelta(days=age - sla), payload={"finding_id": f["id"], "age_days": age, "sla_days": sla})
                observed.add(key)
                counts["services"] += 1

    # Professional services: a deliverable the client has not accepted past the
    # nudge window, and an engagement still open past its planned end date.
    for e in engagements(db):
        mod = e["_module"]
        subj = e.get("subject") or {}
        pub = reach.public_url(mod)
        link = f"{pub}/engagements/{e['id']}" if pub else ""
        common = dict(source=mod, domain="services", client=subj.get("client", ""),
                      platform_client_id=subj.get("platform_client_id") or "", link=link)
        for d in e.get("deliverables") or []:
            if d.get("status") != "delivered":
                continue
            delivered = d.get("delivered_at")
            try:
                at = dt.datetime.fromisoformat(delivered) if delivered else None
            except ValueError:
                at = None
            if at is not None and at.tzinfo is None:
                at = at.replace(tzinfo=dt.timezone.utc)
            age = (now - at).days if at is not None else 0
            if age <= settings.acceptance_nudge_days:
                continue
            key = f"acceptance:{mod}:{d['id']}"
            _upsert(db, key, kind="acceptance", severity="low",
                    title=f"Awaiting client acceptance {age}d: {d.get('title', '')} ({e.get('name', '')})"[:400],
                    due_at=now - dt.timedelta(days=age - settings.acceptance_nudge_days),
                    payload={"engagement_id": e["id"], "engagement": e.get("name"), "deliverable_id": d["id"],
                             "deliverable": d.get("title"), "delivered_at": delivered, "age_days": age,
                             "nudge_days": settings.acceptance_nudge_days, "lead": e.get("lead")}, **common)
            observed.add(key)
            counts["services"] += 1
        ends = e.get("ends_on")
        try:
            end_at = dt.datetime.fromisoformat(ends) if ends else None
        except ValueError:
            end_at = None
        if end_at is not None and end_at.tzinfo is None:
            end_at = end_at.replace(tzinfo=dt.timezone.utc)
        if end_at is not None and end_at < now and e.get("status") in ("scoping", "active", "on_hold"):
            over = (now - end_at).days
            key = f"engagement_overdue:{mod}:{e['id']}"
            _upsert(db, key, kind="engagement_overdue", severity="medium",
                    title=f"Engagement {over}d past planned end: {e.get('name', '')}"[:400], due_at=end_at,
                    payload={"engagement_id": e["id"], "engagement": e.get("name"), "kind": e.get("kind"),
                             "status": e.get("status"), "ends_on": ends, "days_over": over, "lead": e.get("lead"),
                             "progress": e.get("progress")}, **common)
            observed.add(key)
            counts["services"] += 1

    # Anything observed before but not now has been handled in its module.
    gone = 0
    for w in db.execute(select(WorkItem).where(WorkItem.state.in_(("open", "claimed")))).scalars().all():
        if w.key in observed or w.source == "sabine":
            continue
        w.state, w.done_at = "gone", now
        gone += 1
    db.commit()
    counts["gone"] = gone
    return counts
