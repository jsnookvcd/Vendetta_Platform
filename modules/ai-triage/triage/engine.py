"""Triage orchestration: ground a model's proposal against the rules, or fall back.

The engine always has the deterministic rules verdict in hand. When an LLM backend is
configured, the engine uses its proposal but grounds it:

  - any failure (network, malformed output, unknown verdict) falls back to rules;
  - when the model and the rules agree, confidence is allowed to stand;
  - when they disagree, confidence is damped and a second approver is forced, and the
    disagreement is written into the rationale and signals, so the record shows the
    model was second-guessed rather than followed blindly.

The result is a single Proposal. It is advice: the module still requires a human to
accept it, and a second approver for high-stakes or low-confidence verdicts. Both the
proposal and the human decision go into the signed evidence chain.
"""
from __future__ import annotations

import logging

from . import rules
from .model import Finding, Proposal, requires_second_approver

log = logging.getLogger(__name__)


def triage(finding: Finding, backend=None) -> Proposal:
    """Produce a grounded triage Proposal for a finding. With no backend, this is the
    rules verdict. With an LLM backend, the model's verdict grounded against the rules."""
    baseline = rules.propose(finding)
    if backend is None:
        return baseline

    try:
        proposed = backend.propose(finding)
    except Exception as e:  # noqa: BLE001
        log.warning("triage: LLM backend failed (%s); falling back to rules", type(e).__name__)
        fb = rules.propose(finding)
        fb.signals = [*fb.signals, f"LLM backend unavailable ({type(e).__name__}); used rules fallback"]
        return fb

    return _ground(proposed, baseline)


def _ground(model_proposal: Proposal, rules_proposal: Proposal) -> Proposal:
    """Reconcile a model proposal with the rules baseline."""
    if model_proposal.verdict == rules_proposal.verdict:
        model_proposal.signals = [
            *model_proposal.signals,
            f"rules engine ({rules_proposal.model}) agrees: {rules_proposal.verdict}",
        ]
        model_proposal.requires_approval = requires_second_approver(
            model_proposal.verdict, model_proposal.confidence)
        return model_proposal

    # Disagreement: dampen confidence, force a second approver, record both views.
    damped = min(model_proposal.confidence, 0.6)
    model_proposal.confidence = round(damped, 3)
    model_proposal.requires_approval = True
    model_proposal.rationale = (
        model_proposal.rationale
        + f" Note: the deterministic rules engine instead suggests "
          f"'{rules_proposal.verdict}' ({rules_proposal.rationale}) A human must reconcile these."
    )
    model_proposal.signals = [
        *model_proposal.signals,
        f"DISAGREEMENT: rules engine suggests {rules_proposal.verdict}; confidence damped and "
        f"second approver required",
    ]
    return model_proposal


def build_backend(settings) -> object | None:
    """Construct an LLM backend from a settings object if configured, else None (rules
    only). Looks for triage_llm_api_key and triage_llm_model attributes."""
    api_key = getattr(settings, "triage_llm_api_key", "") or ""
    model = getattr(settings, "triage_llm_model", "") or ""
    if not (api_key and model):
        return None
    from .llm import LLMBackend
    base_url = getattr(settings, "triage_llm_base_url", "") or "https://api.anthropic.com"
    return LLMBackend(api_key=api_key, model=model, base_url=base_url)
