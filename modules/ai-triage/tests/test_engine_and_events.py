"""Grounding an LLM proposal against the rules, the fallback on failure, and the
signed-evidence event contract."""
import pytest

from triage import Finding, Proposal, triage
from triage.evidence_events import decision_event, proposal_event


class _FakeBackend:
    def __init__(self, proposal=None, boom=False):
        self._p = proposal
        self._boom = boom

    def propose(self, f):
        if self._boom:
            raise RuntimeError("model unreachable")
        return self._p


def _finding():
    return Finding(title="RCE", description="Unauthenticated RCE", severity="critical",
                   cvss=9.8, cve="CVE-2026-1", source="vulnerability-management")


def test_backend_failure_falls_back_to_rules():
    p = triage(_finding(), backend=_FakeBackend(boom=True))
    assert p.model == "rules-v1"
    assert any("fallback" in s.lower() for s in p.signals)


def test_agreement_keeps_model_verdict_and_notes_rules():
    model_p = Proposal(verdict="true_positive", confidence=0.9, rationale="clearly RCE",
                       signals=["unauth RCE"], model="claude-x", requires_approval=False)
    p = triage(_finding(), backend=_FakeBackend(model_p))
    assert p.verdict == "true_positive" and p.model == "claude-x"
    assert any("rules engine" in s and "agrees" in s for s in p.signals)


def test_disagreement_damps_confidence_and_forces_approval():
    # Model says false_positive on a critical RCE; rules say true_positive.
    model_p = Proposal(verdict="false_positive", confidence=0.95, rationale="looks benign",
                       signals=["hunch"], model="claude-x", requires_approval=False)
    p = triage(_finding(), backend=_FakeBackend(model_p))
    assert p.verdict == "false_positive"           # model's verdict is surfaced
    assert p.confidence <= 0.6                       # but damped
    assert p.requires_approval is True               # and a second approver is forced
    assert any("DISAGREEMENT" in s for s in p.signals)
    assert "rules engine" in p.rationale


def test_proposal_event_attributes_to_copilot():
    p = triage(_finding())
    kind, actor, detail, payload = proposal_event(p)
    assert kind == "triage_proposed"
    assert actor.startswith("copilot:")
    assert payload["verdict"] == p.verdict and "confidence" in payload and "rationale" in payload


def test_decision_event_records_human_and_approver():
    p = triage(_finding())
    kind, actor, detail, payload = decision_event(
        decision="accepted", actor="analyst@vendettacd.io", proposal=p, approver="lead@vendettacd.io")
    assert kind == "triage_decided" and actor == "analyst@vendettacd.io"
    assert payload["approver"] == "lead@vendettacd.io" and payload["decision"] == "accepted"
    assert payload["model"] == p.model


def test_decision_event_rejects_unknown_decision():
    p = triage(_finding())
    with pytest.raises(ValueError):
        decision_event(decision="deleted", actor="a@b.c", proposal=p)
