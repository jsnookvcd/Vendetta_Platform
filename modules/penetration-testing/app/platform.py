"""The shared finding model and escalation to the engagement hub."""
from __future__ import annotations

import logging

import httpx

from .config import settings
from .db import Finding

log = logging.getLogger(__name__)

_STATUS = {"open": "confirmed", "remediating": "reviewing", "retest_pending": "reviewing",
           "retest_passed": "closed", "accepted": "closed", "false_positive": "false_positive"}


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "module": "penetration-testing",
        "platform": "Vendetta Platform",
        "subject": {"client_id": f.client_id, "platform_client_id": f.engagement.client.platform_client_id,
                    "client": f.engagement.client.name, "case_ref": f.engagement.name},
        "type": "pentest-finding",
        "reason": f.engagement.kind,
        "severity": f.severity if f.severity != "info" else "low",
        "status": _STATUS.get(f.status, "confirmed"),
        "title": f.title,
        "matched": f.asset,
        "cve": f.cve,
        "cvss": f.cvss,
        "source_group": f.engagement.name,
        "url": "",
        "published_at": f.created_at.isoformat() if f.created_at else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "analyst_notes": f.remediation,
        "evidence": f.evidence or [],
        "workstream": "Resilience and Hardening",
    }


def escalate(f: Finding) -> dict:
    if not settings.platform_hub_url:
        return {"escalated": False, "reason": "hub not configured"}
    payload = {
        "platform_client_id": f.engagement.client.platform_client_id,
        "client": f.engagement.client.name,
        "severity": f.severity if f.severity != "info" else "low",
        "title": f"[Pentest] {f.title}" + (f" on {f.asset}" if f.asset else ""),
        "workstream": "Resilience and Hardening",
        "source_module": "penetration-testing",
        "case_ref": f.engagement.name,
        "finding": finding_dict(f),
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
