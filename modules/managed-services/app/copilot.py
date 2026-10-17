"""Triage copilot glue: the vendored ai-triage library applied to this module's alerts.

The copilot proposes a verdict for an alert; it never changes the alert. The proposal
is stored on the alert (Alert.copilot) for the pages and the finding API, and signed
into the per-client action chain as a triage_proposed row attributed to the copilot.
When a human accepts, rejects or overrides it, the decision is signed into the same
chain as a triage_decided row attributed to the analyst, naming the approver when the
action needed one. Closing an alert on the copilot's word is a high-stakes action and
goes through the module's existing approver rules (see main.py)."""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import ActionLog, Alert, utcnow
from .triage import Finding, Proposal, build_backend, triage
from .triage.evidence_events import decision_event, proposal_event
from .triage.model import VERDICT_NAMES, VERDICTS

# Verdicts whose acceptance closes the alert here (resolve on this console). The
# two-person rule applies to these.
CLOSING_VERDICTS = ("false_positive", "benign_expected", "duplicate")

@lru_cache(maxsize=1)
def backend():
    """The configured LLM backend, or None for the rules backend. Cached per process;
    settings are read once at boot."""
    return build_backend(settings)


def reset_backend() -> None:
    backend.cache_clear()


def _prior_verdict(db: Session, alert: Alert) -> str:
    """A human's most recent final verdict for the same client, tool and signature
    (title), on another alert. The strongest evidence the rules backend has."""
    rows = db.execute(
        select(Alert.copilot).where(Alert.client_id == alert.client_id, Alert.tool == alert.tool,
                                    Alert.title == alert.title, Alert.id != alert.id,
                                    Alert.copilot.isnot(None))
        .order_by(Alert.updated_at.desc()).limit(10)
    ).scalars().all()
    for cp in rows:
        decision = (cp or {}).get("decision") or {}
        if decision.get("decision") in ("accepted", "overridden") and decision.get("final_verdict") in VERDICTS:
            return decision["final_verdict"]
    return ""


def to_finding(db: Session, alert: Alert) -> Finding:
    times_seen = db.scalar(select(func.count(Alert.id)).where(
        Alert.client_id == alert.client_id, Alert.tool == alert.tool, Alert.title == alert.title)) or 1
    return Finding(
        id=alert.id,
        title=alert.title or "",
        description=alert.detail or "",
        severity=alert.severity or "",
        asset=alert.device.hostname if alert.device else "",
        source=alert.tool or "",
        status=alert.status or "",
        first_seen=alert.received_at.isoformat() if alert.received_at else "",
        times_seen=int(times_seen),
        prior_verdict=_prior_verdict(db, alert),
        tags=[alert.kind] if alert.kind else [],
        extra={"tool_status": alert.tool_status},
    )


def _stored(proposal: Proposal) -> dict:
    return {**proposal.to_event_payload(), "created_at": utcnow().isoformat()}


def propose(db: Session, alert: Alert) -> Proposal:
    """Compute the copilot's proposal for an alert, store it on the alert and sign it
    into the client's action chain. Recomputing replaces the stored proposal and
    appends a new chain row; the earlier row stays in the chain. Does not commit."""
    if alert.id is None:
        db.flush()
    proposal = triage(to_finding(db, alert), backend=backend())
    kind, actor, detail, payload = proposal_event(proposal)
    db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, device_id=alert.device_id,
                     tool=alert.tool, action=kind, actor=actor, detail=detail, payload=payload))
    alert.copilot = _stored(proposal)
    return proposal


def from_stored(data: dict | None) -> Proposal | None:
    """Rebuild a Proposal from Alert.copilot so a decision can be recorded against
    exactly what was proposed."""
    if not data or data.get("verdict") not in VERDICTS:
        return None
    return Proposal(verdict=data["verdict"], confidence=float(data.get("confidence", 0.0)),
                    rationale=data.get("rationale", ""), signals=list(data.get("signals") or []),
                    model=data.get("model", ""), requires_approval=bool(data.get("requires_approval")),
                    suggested_action=data.get("suggested_action", ""))


def decide(db: Session, alert: Alert, *, decision: str, final_verdict: str, actor: str,
           approver: str = "", note: str = "") -> tuple[str, str, str, dict]:
    """Sign the human's disposition of the stored proposal into the chain and record
    it on the alert. The caller applies the resulting status change and has already
    resolved the approver under the module's two-person rule. Does not commit."""
    proposal = from_stored(alert.copilot)
    if proposal is None:
        raise ValueError("no copilot proposal on this alert")
    kind, who, detail, payload = decision_event(decision=decision, actor=actor, proposal=proposal,
                                                note=note, approver=approver)
    payload["final_verdict"] = final_verdict
    db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, device_id=alert.device_id,
                     tool=alert.tool, action=kind, actor=who, approver=approver, detail=detail,
                     payload=payload))
    alert.copilot = {**alert.copilot, "decision": {
        "decision": decision, "final_verdict": final_verdict, "analyst": actor,
        "approver": approver, "note": note, "at": utcnow().isoformat()}}
    return kind, who, detail, payload


def verdict_name(verdict: str) -> str:
    return VERDICT_NAMES.get(verdict, verdict)


def summary(data: dict | None) -> dict | None:
    """The finding-model view of a stored proposal: what SABINE and the hub read."""
    if not data or data.get("verdict") not in VERDICTS:
        return None
    out = {
        "verdict": data["verdict"],
        "confidence": float(data.get("confidence", 0.0)),
        "rationale": data.get("rationale", ""),
        "model": data.get("model", ""),
        "requires_approval": bool(data.get("requires_approval")),
        "created_at": data.get("created_at"),
        "decision": None,
    }
    d = data.get("decision")
    if d:
        out["decision"] = {"decision": d.get("decision"), "final_verdict": d.get("final_verdict"),
                           "analyst": d.get("analyst"), "approver": d.get("approver", ""), "at": d.get("at")}
    return out
