"""Map triage into the signed evidence chain.

The copilot's proposal and the human's decision are both evidentiary: the record must
show what the copilot recommended, how confident it was and why, and then who accepted,
rejected or overrode it. These helpers return the (kind, actor, detail, payload) a
module passes to its own record_event, so every module writes triage into its chain the
same way. Nothing here mutates a finding; executing the decision stays with the module,
behind its RBAC and two-person approval.
"""
from __future__ import annotations

from .model import DECISIONS, VERDICT_NAMES, Proposal


def proposal_event(proposal: Proposal) -> tuple[str, str, str, dict]:
    """Event for the copilot's recommendation. The actor is the copilot, named with its
    model, so a model's judgment is never attributed to a person."""
    actor = f"copilot:{proposal.model}"
    detail = (f"proposed {VERDICT_NAMES.get(proposal.verdict, proposal.verdict)} "
              f"({proposal.confidence:.0%} confidence)")
    return "triage_proposed", actor, detail, proposal.to_event_payload()


def decision_event(*, decision: str, actor: str, proposal: Proposal,
                   note: str = "", approver: str = "") -> tuple[str, str, str, dict]:
    """Event for the human's disposition of a proposal.

    decision   one of accepted | rejected | overridden
    actor      the human analyst (never the copilot)
    approver   the second approver, when the action required one
    """
    if decision not in DECISIONS:
        raise ValueError(f"unknown triage decision: {decision!r}")
    detail = f"{decision} copilot proposal ({VERDICT_NAMES.get(proposal.verdict, proposal.verdict)})"
    if approver:
        detail += f"; approved by {approver}"
    payload = {
        "decision": decision,
        "analyst": actor,
        "approver": approver,
        "note": note,
        "proposed_verdict": proposal.verdict,
        "proposed_confidence": round(proposal.confidence, 3),
        "model": proposal.model,
        "required_approval": proposal.requires_approval,
    }
    return "triage_decided", actor, detail, payload
