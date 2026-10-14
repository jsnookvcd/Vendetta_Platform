"""The shapes the triage copilot works with.

A Finding is the normalized input: whatever a module knows about one detection. A
Proposal is what the copilot returns: a recommended verdict, a calibrated confidence,
a written rationale, the signals that drove it, and whether acting on it needs a second
approver. A Proposal is never an action; it is advice that a human accepts or rejects,
and both the proposal and that human decision are written into the signed evidence
chain, so the record shows what the copilot said, how sure it was, why, and who decided.
"""
from __future__ import annotations

import dataclasses
from typing import Any

# Verdicts the copilot can recommend for a finding.
VERDICTS = [
    "true_positive",      # a real issue; act on it
    "false_positive",     # not a real issue; close it
    "needs_investigation",  # not enough to call; a human should look
    "duplicate",          # already tracked by another finding
    "benign_expected",    # real but expected/authorized (e.g. a sanctioned scanner)
]
VERDICT_NAMES = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "needs_investigation": "Needs investigation",
    "duplicate": "Duplicate",
    "benign_expected": "Benign / expected",
}

# Verdicts whose downstream action is destructive or client-visible enough that the
# platform's two-person rule applies before anything is executed.
_HIGH_STAKES = {"false_positive", "benign_expected", "duplicate"}

# How a human dispositioned a proposal.
DECISIONS = ["accepted", "rejected", "overridden"]


@dataclasses.dataclass
class Finding:
    """Normalized triage input. Modules map their own finding row onto this."""
    id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""           # info|low|medium|high|critical
    cvss: float | None = None
    asset: str = ""
    cve: str = ""
    source: str = ""             # the tool/module that produced it
    status: str = ""
    first_seen: str = ""
    times_seen: int = 1          # recurrence count (dedup history)
    prior_verdict: str = ""      # a human's past verdict for the same asset+signature, if any
    tags: list[str] = dataclasses.field(default_factory=list)
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Proposal:
    verdict: str
    confidence: float            # 0.0 .. 1.0, calibrated
    rationale: str               # written explanation, human-readable
    signals: list[str]           # the concrete factors that drove the verdict
    model: str                   # "rules-v1" or the LLM model id
    requires_approval: bool      # a second approver needed before the action executes
    suggested_action: str = ""   # optional next step, still subject to human + approver

    def to_event_payload(self) -> dict:
        """The payload written into the signed evidence chain for a 'triage_proposed'
        event. Everything the copilot asserted is captured, so the record is complete."""
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "signals": self.signals,
            "model": self.model,
            "requires_approval": self.requires_approval,
            "suggested_action": self.suggested_action,
        }


def requires_second_approver(verdict: str, confidence: float) -> bool:
    """A second approver is required when acting on the verdict is high-stakes, and
    always when the copilot is not confident. Closing or suppressing a finding the
    copilot is unsure about is exactly where a second set of eyes matters."""
    if verdict in _HIGH_STAKES:
        return True
    if confidence < 0.75:
        return True
    return False
