"""Escalation from a professional-services engagement into the IR hub.

OSP does not feed the shared finding model the way the scanning modules do; its
output is deliverables, not detections. What it does contribute is escalation: a
vCISO or a tabletop that surfaces a live risk opens an IR case on the Resilience and
Hardening workstream, carrying the engagement as the reference.
"""
from __future__ import annotations

import logging

import httpx

from .config import ENGAGEMENT_TYPE_NAMES, settings
from .db import Engagement

log = logging.getLogger(__name__)


def escalate(engagement: Engagement, note: str = "", severity: str = "high") -> dict:
    if not settings.platform_hub_url:
        return {"escalated": False, "reason": "hub not configured"}
    kind = ENGAGEMENT_TYPE_NAMES.get(engagement.kind, engagement.kind)
    payload = {
        "platform_client_id": engagement.client.platform_client_id,
        "client": engagement.client.name,
        "severity": severity,
        "title": f"[{kind}] {engagement.name}" + (f": {note}" if note else ""),
        "workstream": "Resilience and Hardening",
        "source_module": "professional-services",
        "case_ref": engagement.name,
        "detail": note,
    }
    headers = {"Authorization": f"Bearer {settings.platform_hub_token}"} if settings.platform_hub_token else {}
    url = f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases"
    try:
        with httpx.Client(timeout=15.0, headers=headers) as http:
            r = http.post(url, json=payload)
        if r.status_code >= 400:
            return {"escalated": False, "reason": f"hub HTTP {r.status_code}"}
        return {"escalated": True, **(r.json() if r.headers.get("content-type", "").startswith("application/json") else {})}
    except httpx.HTTPError as e:  # noqa: BLE001
        return {"escalated": False, "reason": f"hub unreachable: {type(e).__name__}"}
