"""Vendetta Platform integration: an investigation as a shared finding, and its
escalation into an IR case on the hub (the incident-response module).

POST {PLATFORM_HUB_URL}/api/ir-cases with Bearer PLATFORM_HUB_TOKEN, payload per
docs/contracts/escalation.schema.json, always on the Scoping and Containment
workstream. The returned case number is stored on the investigation, so escalating
again attaches to that case. Escalation is a no-op until the hub URL is set.
"""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import RESPONSE_NAMES, WORKSTREAM, settings
from .db import Investigation, record, utcnow

log = logging.getLogger(__name__)

STATUS_MAP = {"new": "new", "investigating": "reviewing", "contained": "confirmed"}


def _iso(v) -> str | None:
    return v.isoformat() if v else None


def finding_status(inv: Investigation) -> str:
    if inv.status == "closed":
        return "false_positive" if inv.verdict == "false_positive" else "closed"
    return STATUS_MAP.get(inv.status, "new")


def alert_ref(inv: Investigation) -> str:
    s = inv.latest_signal()
    return s.id if s else ""


def alert_link(inv: Investigation) -> str:
    """The managed-services alert page where a responder takes the containment
    action under that module's approval rules. Blank when its public URL is unset."""
    ref = alert_ref(inv)
    base = (settings.managed_services_public_url or "").rstrip("/")
    return f"{base}/alerts/{ref}" if (base and ref) else ""


def finding_dict(inv: Investigation) -> dict:
    c = inv.client
    latest = inv.latest_signal()
    return {
        "id": inv.id,
        "module": "mdr",
        "platform": "Vendetta Platform",
        "subject": {"client_id": inv.client_id, "platform_client_id": c.platform_client_id or "",
                    "client": c.name, "case_ref": inv.escalated_case or ""},
        "type": "investigation",
        "reason": inv.rule_key,
        "severity": inv.severity if inv.severity in ("low", "medium", "high", "critical") else "low",
        "status": finding_status(inv),
        "title": f"{inv.number}: {inv.title}",
        "matched": inv.host or "",
        "source_group": latest.tool if latest else "",
        "url": f"{settings.public_url.rstrip('/')}/investigations/{inv.id}" if settings.public_url else "",
        "published_at": _iso(inv.first_signal_at),
        "created_at": _iso(inv.opened_at),
        "analyst_notes": inv.client_summary or "",
        "evidence": [],
        "workstream": WORKSTREAM,
        "number": inv.number,
        "native_status": inv.status,
        "verdict": inv.verdict,
        "mitre": list(inv.mitre or []),
        "opened_at": _iso(inv.opened_at),
        "acknowledged_at": _iso(inv.acknowledged_at),
        "contained_at": _iso(inv.contained_at),
        "closed_at": _iso(inv.closed_at),
        "response": {"action": inv.response or "none", "host": inv.host or "", "alert_ref": alert_ref(inv)},
        "rule": inv.rule_key,
        "signals": len(inv.links),
        "published": bool(inv.published),
    }


def escalate(inv: Investigation, db: Session, actor: str, note: str = "") -> dict:
    """Open or link an IR case. Returns {escalated, case, linked} or
    {escalated: False, reason}. Never raises."""
    if not settings.platform_hub_url:
        return {"escalated": False, "reason": "PLATFORM_HUB_URL not set; module running standalone"}
    summary = f"MDR {inv.number}: {inv.title}"[:250]
    payload = {
        "source_module": "mdr",
        "client_id": inv.client_id,
        "platform_client_id": inv.client.platform_client_id or None,
        "client": inv.client.name,
        "case_ref": inv.escalated_case or "",  # re-escalating attaches to the same case
        "severity": inv.severity,
        "summary": summary,
        "title": summary,
        "workstream": WORKSTREAM,
        "finding": finding_dict(inv),
    }
    if note:
        payload["detail"] = note[:2000]
    headers = {"Authorization": f"Bearer {settings.platform_hub_token}"} if settings.platform_hub_token else {}
    url = f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases"
    try:
        with httpx.Client(timeout=30.0, headers=headers) as http:
            r = http.post(url, json=payload)
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
    first = not inv.escalated_case
    inv.escalated_case = str(case)[:60]
    if inv.status == "new":
        inv.status = "investigating"
        if not inv.acknowledged_at:
            inv.acknowledged_at, inv.acknowledged_by = utcnow(), actor
    record(db, inv, "escalated", actor,
           f"{'Escalated to' if first else 'Re-escalated to'} IR case {inv.escalated_case} "
           f"({'linked to the open case' if linked else 'new case'}) on {WORKSTREAM}."
           + (f" {note}" if note else ""),
           {"case": inv.escalated_case, "linked": linked, "workstream": WORKSTREAM}, client_visible=True)
    db.commit()
    log.info("escalated %s to hub case %s (linked=%s)", inv.number, inv.escalated_case, linked)
    return {"escalated": True, "case": inv.escalated_case, "linked": linked}


__all__ = ["finding_dict", "escalate", "alert_ref", "alert_link", "RESPONSE_NAMES"]
