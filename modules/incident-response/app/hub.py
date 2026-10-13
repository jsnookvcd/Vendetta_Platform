"""Engagement hub logic: receiving escalations from other modules.

Modules run their own databases, so a module's client_id is not this hub's
client_id. Resolution order for the client: hub id, then exact name match
(case-insensitive), then create the client so the escalation is never dropped.

Link-or-open: if the payload's case_ref names an open hub case, the finding is
attached to that case. Otherwise a new case is opened. Either way the finding
lands on the timeline under the requested workstream, carrying its payload."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import WORKSTREAMS
from .db import AuditLog, Case, CaseUpdate, Client, open_case

VALID_SEV = {"low", "medium", "high", "critical"}


def resolve_client(db: Session, client_id: str, name: str) -> Client:
    c = db.get(Client, client_id) if client_id else None
    if c:
        return c
    if name:
        c = db.execute(select(Client).where(func.lower(Client.name) == name.strip().lower())).scalar_one_or_none()
        if c:
            return c
    c = Client(name=(name or f"Unmapped client {client_id[:8]}").strip()[:200], notes="Created from a module escalation.")
    db.add(c)
    db.commit()
    return c


def retainer_lead(client: Client) -> str:
    """First named responder on an active retainer, or "" when there is none."""
    r = client.retainer
    if r and r.active and r.named_responders:
        return r.named_responders.split(",")[0].strip()
    return ""


def escalate(db: Session, payload: dict, actor: str) -> tuple[Case, bool]:
    """Returns (case, linked). linked is True when attached to an existing open case."""
    finding = payload.get("finding") or {}
    subject = finding.get("subject") or {}
    client = resolve_client(db, payload.get("client_id") or subject.get("client_id") or "",
                            subject.get("client") or payload.get("client") or "")
    sev = payload.get("severity") or finding.get("severity") or "high"
    sev = sev if sev in VALID_SEV else "high"
    ws = payload.get("workstream") or finding.get("workstream") or WORKSTREAMS[0]
    ws = ws if ws in WORKSTREAMS else WORKSTREAMS[0]
    module = payload.get("source_module") or finding.get("module") or "unknown"
    summary = (payload.get("summary") or finding.get("title") or "Escalated finding")[:300]

    case = None
    ref = (payload.get("case_ref") or subject.get("case_ref") or "").strip()
    if ref:
        case = db.execute(select(Case).where(Case.number == ref, Case.status != "closed")).scalar_one_or_none()
    linked = case is not None
    if not case:
        case = open_case(db, client, summary, severity=sev, origin="escalated", actor=actor,
                         lead=retainer_lead(client), source_module=module)
    elif _rank(sev) > _rank(case.severity):
        case.severity = sev  # an escalation can raise, never lower, case severity

    case.updates.append(CaseUpdate(
        workstream=ws, actor=actor, kind="finding", internal_only=True,
        note=f"Finding escalated from {module}: {summary}", payload={"source_module": module, "finding": finding},
    ))
    db.add(AuditLog(actor=actor, action="case.escalation", detail=f"{case.number} <- {module} linked={linked}"))
    db.commit()
    return case, linked


def _rank(sev: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(sev, 0)
