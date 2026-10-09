"""VERDICT platform integration.

Exposes dark web hits as platform findings and lets the engagement hub escalate a
finding into an IR case. The platform treats every module's output as a finding
with a severity, a verdict and evidence, so this maps the module's Hit rows into
that shape. Escalation is a no-op until VERDICT_HUB_URL is configured, which keeps
the module standalone until the hub is live."""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .db import Evidence, Hit, utcnow

log = logging.getLogger(__name__)

# Hit.status -> platform verdict vocabulary (same words; kept explicit so a future
# divergence in the hub's vocabulary is a one-line change here).
VERDICT = {
    "new": "new",
    "reviewing": "reviewing",
    "confirmed": "confirmed",
    "false_positive": "false_positive",
    "closed": "closed",
}


def finding_dict(hit: Hit, db: Session) -> dict:
    item = hit.item
    client = hit.client
    ev = db.query(Evidence).filter(Evidence.item_id == hit.item_id).all()
    return {
        "id": hit.id,
        "module": "dark-web-monitoring",
        "platform": "VERDICT",
        "subject": {"client_id": client.id, "client": client.name, "case_ref": client.case_ref},
        "type": item.kind,
        "reason": hit.reason,
        "severity": hit.severity,
        "verdict": VERDICT.get(hit.status, hit.status),
        "title": item.title,
        "matched": hit.matched_text,
        "source_group": item.group_name,
        "url": item.url,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "created_at": hit.created_at.isoformat(),
        "analyst_notes": hit.analyst_notes,
        "evidence": [
            {"id": e.id, "sha256": e.sha256, "captured_at": e.captured_at.isoformat(), "storage_uri": e.storage_uri}
            for e in ev
        ],
        "alert_refs": hit.alert_refs,
        "workstream": "Forensics and Analysis",
    }


def escalate(hit: Hit, db: Session) -> dict:
    """Open or link an IR case in the engagement hub for this finding.
    Returns {"escalated": False, ...} when the hub is not configured."""
    if not settings.verdict_hub_url:
        return {"escalated": False, "reason": "VERDICT_HUB_URL not set; module running standalone"}
    payload = {
        "source_module": "dark-web-monitoring",
        "client_id": hit.client_id,
        "case_ref": hit.client.case_ref,
        "severity": hit.severity,
        "summary": f"Dark web {hit.reason} finding: {hit.item.title}"[:250],
        "finding": finding_dict(hit, db),
        "workstream": "Forensics and Analysis",
    }
    headers = {"Authorization": f"Bearer {settings.verdict_hub_token}"} if settings.verdict_hub_token else {}
    r = httpx.post(f"{settings.verdict_hub_url.rstrip('/')}/api/ir-cases", json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    body = r.json()
    refs = dict(hit.alert_refs or {})
    refs["verdict_case"] = body.get("case_id") or body.get("id") or "linked"
    hit.alert_refs = refs
    hit.status = "reviewing" if hit.status == "new" else hit.status
    db.add(hit)
    db.commit()
    log.info("escalated hit %s to VERDICT hub case %s", hit.id, refs["verdict_case"])
    return {"escalated": True, "case": refs["verdict_case"]}
