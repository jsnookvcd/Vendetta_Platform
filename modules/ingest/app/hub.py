"""Vendetta Platform integration: a detection as a shared finding, and its escalation
into an IR case on the hub (the incident-response module).

MDR reads these findings as signals, next to the managed-services alerts. Each
finding's evidence lists the events behind the detection with their normalized-event
hash and a link to the event's signed inclusion proof, so an investigation, a case or
a court exhibit can cite telemetry that is proven to have arrived unaltered.
"""
from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import SEVERITIES, WORKSTREAM, settings
from .db import AuditLog, Client, Detection, Event
from .stream import tool_of

log = logging.getLogger(__name__)

EVIDENCE_LIMIT = 25


def _iso(v) -> str | None:
    return v.isoformat() if v else None


def finding_type(d: Detection) -> str:
    return "sigma" if d.kind == "sigma" else "alert"


def evidence_for(db: Session, d: Detection, limit: int = EVIDENCE_LIMIT) -> list[dict]:
    ids = list(d.event_ids or [])[-limit:]
    if not ids:
        return []
    base = (settings.public_url or "").rstrip("/")
    rows = db.execute(select(Event.id, Event.event_sha256, Event.received_at, Event.batch_id)
                      .where(Event.id.in_(ids), Event.tenant == d.tenant)).all()
    return [{"id": r.id, "sha256": r.event_sha256, "captured_at": _iso(r.received_at),
             "storage_uri": f"{base}/api/events/{r.id}/proof" if base else f"/api/events/{r.id}/proof",
             "sealed": bool(r.batch_id)} for r in rows]


def finding_dict(d: Detection, client: Client, evidence: list[dict] | None = None) -> dict:
    sev = d.severity if d.severity in SEVERITIES else "low"
    return {
        "id": d.id,
        "module": "ingest",
        "platform": "Vendetta Platform",
        "subject": {"client_id": client.id, "platform_client_id": client.platform_client_id or "",
                    "client": client.name, "case_ref": d.escalated_case or ""},
        "type": finding_type(d),
        "reason": tool_of(d.source),
        "severity": sev,
        "status": d.status,
        "title": d.title,
        "matched": d.host or d.user or "",
        "source_group": d.source,
        "url": f"{settings.public_url.rstrip('/')}/detections/{d.id}" if settings.public_url else "",
        "published_at": _iso(d.first_event_at),
        "created_at": _iso(d.created_at),
        "analyst_notes": d.note or "",
        "evidence": evidence if evidence is not None else [],
        "workstream": WORKSTREAM,
        "rule": d.rule_id or None,
        "rule_title": d.rule_title or None,
        "kind": d.kind,
        "mitre": list(d.mitre or []),
        "events": d.count,
        "last_event_at": _iso(d.last_event_at),
        "user": d.user or "",
        # The source tool and the vendor's own id, so MDR can tell this alert and the
        # managed-services copy of the same alert apart from two separate alerts.
        "alert_refs": {"tool": tool_of(d.source), "vendor_id": d.group_key.split(":", 1)[1]}
        if d.kind == "vendor" and ":" in (d.group_key or "") else None,
    }


def escalate(db: Session, d: Detection, actor: str, note: str = "") -> dict:
    """Open or link an IR case. Returns {escalated, case, linked} or
    {escalated: False, reason}. Never raises."""
    if not settings.platform_hub_url:
        return {"escalated": False, "reason": "PLATFORM_HUB_URL not set; module running standalone"}
    client = db.get(Client, d.client_id)
    if client is None:
        return {"escalated": False, "reason": "detection has no client"}
    summary = f"Telemetry detection: {d.title}"[:250]
    payload = {
        "source_module": "ingest", "client_id": client.id,
        "platform_client_id": client.platform_client_id or None, "client": client.name,
        "case_ref": d.escalated_case or "", "severity": d.severity if d.severity in SEVERITIES else "low",
        "summary": summary, "title": summary, "workstream": WORKSTREAM,
        "finding": finding_dict(d, client, evidence_for(db, d)),
    }
    if note:
        payload["detail"] = note[:2000]
    headers = {"Authorization": f"Bearer {settings.platform_hub_token}"} if settings.platform_hub_token else {}
    try:
        with httpx.Client(timeout=30.0, headers=headers) as http:
            r = http.post(f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases", json=payload)
    except httpx.HTTPError as e:
        return {"escalated": False, "reason": f"hub unreachable: {type(e).__name__}"}
    if r.status_code >= 400:
        return {"escalated": False, "reason": f"hub HTTP {r.status_code}"}
    try:
        body = r.json()
    except ValueError:
        return {"escalated": False, "reason": "hub answered without JSON"}
    case = body.get("case_id") or body.get("id") or ""
    if not case:
        return {"escalated": False, "reason": "hub answered without a case number"}
    linked = bool(body.get("linked", False))
    d.escalated_case = str(case)[:60]
    if d.status == "new":
        d.status = "reviewing"
    db.add(AuditLog(actor=actor, action="detection.escalate", detail=f"{d.id} -> {d.escalated_case}"))
    db.commit()
    return {"escalated": True, "case": d.escalated_case, "linked": linked}
