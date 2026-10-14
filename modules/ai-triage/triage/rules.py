"""The rules-based triage backend.

This is the default and the fallback: it needs no model, no network and no key, and it
is fully deterministic, so its verdict and confidence can be reproduced and defended.
Every point of score is tied to a named signal, and those signals become the written
rationale, so the copilot never asserts anything it cannot show its work for.

It is deliberately conservative: when signals are weak or conflict, it returns
needs_investigation at low confidence, which routes the finding to a human rather than
auto-dispositioning it.
"""
from __future__ import annotations

from .model import Finding, Proposal, requires_second_approver

MODEL = "rules-v1"

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_AUTHORIZED_TAGS = {"authorized-scan", "sanctioned", "approved", "known-good", "pentest"}
_AUTHORIZED_SOURCES = {"pci-asv", "penetration-testing", "vendetta-scanner"}


def propose(f: Finding) -> Proposal:
    scores: dict[str, float] = {v: 0.0 for v in
                               ("true_positive", "false_positive", "needs_investigation",
                                "duplicate", "benign_expected")}
    signals: list[str] = []

    # A human's prior call on the same asset+signature is the strongest evidence.
    if f.prior_verdict:
        pv = f.prior_verdict
        if pv in scores:
            scores[pv] += 5.0
            signals.append(f"a human previously dispositioned this asset/signature as "
                           f"{pv.replace('_', ' ')}")

    # Authorized / expected activity.
    if set(t.lower() for t in f.tags) & _AUTHORIZED_TAGS or f.source.lower() in _AUTHORIZED_SOURCES:
        scores["benign_expected"] += 3.0
        signals.append(f"source or tags mark this as authorized activity "
                       f"(source={f.source or 'n/a'}, tags={','.join(f.tags) or 'none'})")

    # Recurrence suggests either a persistent real issue or a known duplicate.
    if f.times_seen >= 5:
        scores["duplicate"] += 1.5
        scores["true_positive"] += 0.5
        signals.append(f"seen {f.times_seen} times across scans (recurring)")
    if "duplicate" in (t.lower() for t in f.tags):
        scores["duplicate"] += 3.0
        signals.append("tagged as a duplicate")

    # Severity / CVSS push toward a real issue worth acting on.
    rank = _SEVERITY_RANK.get(f.severity.lower(), -1)
    if rank >= 3:
        scores["true_positive"] += 2.5
        signals.append(f"{f.severity} severity" + (f" (CVSS {f.cvss})" if f.cvss else ""))
    elif rank == 2:
        scores["true_positive"] += 1.0
        signals.append("medium severity")
    elif rank in (0, 1):
        scores["needs_investigation"] += 0.5
        signals.append(f"{f.severity} severity carries little weight on its own")
    if f.cvss is not None and f.cvss >= 9.0:
        scores["true_positive"] += 1.0
        signals.append(f"critical CVSS {f.cvss}")

    # A named CVE with detail is corroborating; a bare title with no detail is not.
    if f.cve:
        scores["true_positive"] += 0.8
        signals.append(f"carries a CVE identifier ({f.cve})")
    if not f.description.strip():
        scores["needs_investigation"] += 1.0
        signals.append("no description provided, so the finding cannot be confirmed from its text")

    # Pick the verdict and derive calibrated confidence from the margin.
    verdict = max(scores, key=lambda k: scores[k])
    top = scores[verdict]
    ordered = sorted(scores.values(), reverse=True)
    runner_up = ordered[1] if len(ordered) > 1 else 0.0

    if top <= 0.0:
        verdict = "needs_investigation"
        confidence = 0.30
        signals.append("no decisive signals")
    else:
        margin = top - runner_up
        # confidence grows with both the absolute evidence and the margin over the next
        # best verdict, capped so the rules engine never claims near-certainty.
        confidence = min(0.92, 0.45 + 0.09 * top + 0.08 * margin)
        if verdict == "needs_investigation":
            confidence = min(confidence, 0.6)

    rationale = _rationale(verdict, signals)
    return Proposal(
        verdict=verdict,
        confidence=round(confidence, 3),
        rationale=rationale,
        signals=signals,
        model=MODEL,
        requires_approval=requires_second_approver(verdict, confidence),
        suggested_action=_suggested_action(verdict),
    )


def _rationale(verdict: str, signals: list[str]) -> str:
    lead = {
        "true_positive": "Recommends treating this as a real issue to act on",
        "false_positive": "Recommends closing this as not a real issue",
        "needs_investigation": "Cannot be called from the available signals; recommends a human review",
        "duplicate": "Appears to duplicate an already-tracked finding",
        "benign_expected": "Appears to be real but authorized or expected activity",
    }[verdict]
    if signals:
        return lead + ", based on: " + "; ".join(signals) + "."
    return lead + "."


def _suggested_action(verdict: str) -> str:
    return {
        "true_positive": "open or escalate for remediation",
        "false_positive": "close as a false positive (requires a second approver)",
        "needs_investigation": "assign to an analyst for review",
        "duplicate": "link to the existing finding and close (requires a second approver)",
        "benign_expected": "mark as expected and suppress recurrences (requires a second approver)",
    }[verdict]
