"""Vendetta Platform integration: expose alerts as platform findings and escalate
an alert into an IR case in the engagement hub (the incident-response module).

Same contract as the dark web module: POST {PLATFORM_HUB_URL}/api/ir-cases with
Bearer PLATFORM_HUB_TOKEN. Escalation is a no-op until the hub URL is set."""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from . import copilot
from .config import TOOL_NAMES, settings
from .db import Alert

log = logging.getLogger(__name__)

# Which hub workstream a finding lands on, by what kind of alert it is.
WORKSTREAM_BY_KIND = {
    "threat": "Scoping and Containment",
    "detection": "Scoping and Containment",
    "incident": "Scoping and Containment",
    "backup": "Recovery and Restoration",
    "rmm": "Scoping and Containment",
}


def finding_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "module": "managed-services",
        "platform": "Vendetta Platform",
        "subject": {"client_id": alert.client_id, "platform_client_id": alert.client.platform_client_id,
                    "client": alert.client.name, "case_ref": ""},
        "type": alert.kind,
        "reason": alert.tool,
        "severity": alert.severity if alert.severity != "info" else "low",
        "status": {"open": "new", "acknowledged": "reviewing", "resolved": "closed"}[alert.status],
        "title": alert.title,
        "matched": alert.device.hostname if alert.device else "",
        "source_group": TOOL_NAMES.get(alert.tool, alert.tool),
        "url": alert.link,
        "published_at": alert.occurred_at.isoformat() if alert.occurred_at else None,
        "created_at": alert.synced_at.isoformat(),
        "analyst_notes": alert.client_note,
        "evidence": [],
        "workstream": WORKSTREAM_BY_KIND.get(alert.kind, "Scoping and Containment"),
        "copilot": copilot.summary(alert.copilot),
    }


def escalate(alert: Alert, db: Session) -> dict:
    if not settings.platform_hub_url:
        return {"escalated": False, "reason": "PLATFORM_HUB_URL not set; module running standalone"}
    payload = {
        "source_module": "managed-services",
        "client_id": alert.client_id,
        "platform_client_id": alert.client.platform_client_id,
        "client": alert.client.name,
        "case_ref": alert.escalated_case or "",  # re-escalating attaches to the same case
        "severity": alert.severity if alert.severity != "info" else "low",
        "summary": f"{TOOL_NAMES.get(alert.tool, alert.tool)} {alert.kind}: {alert.title}"[:250],
        "title": f"{TOOL_NAMES.get(alert.tool, alert.tool)} {alert.kind}: {alert.title}"[:250],
        "finding": finding_dict(alert),
        "workstream": WORKSTREAM_BY_KIND.get(alert.kind, "Scoping and Containment"),
    }
    headers = {"Authorization": f"Bearer {settings.platform_hub_token}"} if settings.platform_hub_token else {}
    r = httpx.post(f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases",
                   json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    body = r.json()
    alert.escalated_case = body.get("case_id") or body.get("id") or "escalated"
    if alert.status == "open":
        alert.status = "acknowledged"
    db.commit()
    log.info("escalated alert %s to hub case %s", alert.id, alert.escalated_case)
    return {"escalated": True, "case": alert.escalated_case, "linked": body.get("linked", False)}
