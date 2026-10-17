"""Vendetta evidence-grounded triage copilot.

    from triage import Finding, triage, build_backend
    from triage.evidence_events import proposal_event, decision_event

The copilot proposes; a human decides; a second approver is required for high-stakes or
low-confidence verdicts. The rules backend is always available and deterministic; an LLM
backend is optional and is grounded against the rules. Both the proposal and the human
decision are written to the signed evidence chain.
"""
from .engine import build_backend, triage
from .model import (DECISIONS, VERDICT_NAMES, VERDICTS, Finding, Proposal,
                    requires_second_approver)

__all__ = ["Finding", "Proposal", "triage", "build_backend", "requires_second_approver",
           "VERDICTS", "VERDICT_NAMES", "DECISIONS"]
