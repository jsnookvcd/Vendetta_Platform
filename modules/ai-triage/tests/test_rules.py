"""The deterministic rules backend: verdicts follow the signals, confidence is bounded,
and weak or missing evidence routes to a human rather than auto-dispositioning."""
from triage import Finding, triage
from triage.model import requires_second_approver


def test_high_severity_cve_is_true_positive():
    p = triage(Finding(title="RCE in web server", description="Unauthenticated RCE",
                       severity="critical", cvss=9.8, cve="CVE-2026-1111", source="vulnerability-management"))
    assert p.verdict == "true_positive"
    assert p.confidence >= 0.7
    assert any("critical" in s.lower() or "cvss" in s.lower() for s in p.signals)
    assert p.model == "rules-v1"


def test_authorized_scanner_is_benign_expected_and_needs_approval():
    p = triage(Finding(title="Port scan from 10.0.0.9", description="Sweep",
                       severity="medium", source="pci-asv", tags=["authorized-scan"]))
    assert p.verdict == "benign_expected"
    # Suppressing expected activity is high-stakes, so a second approver is required.
    assert p.requires_approval is True


def test_prior_human_verdict_dominates():
    p = triage(Finding(title="Legacy TLS", description="TLS 1.0 enabled", severity="low",
                       prior_verdict="false_positive"))
    assert p.verdict == "false_positive"
    assert any("previously dispositioned" in s for s in p.signals)


def test_no_signals_routes_to_investigation_low_confidence():
    p = triage(Finding(title="Unknown", description="", severity=""))
    assert p.verdict == "needs_investigation"
    assert p.confidence <= 0.6


def test_confidence_is_bounded():
    p = triage(Finding(title="x", description="y", severity="critical", cvss=10.0,
                       cve="CVE-2026-2", prior_verdict="true_positive", times_seen=9))
    assert 0.0 <= p.confidence <= 0.92


def test_requires_second_approver_rule():
    assert requires_second_approver("false_positive", 0.99) is True   # high-stakes
    assert requires_second_approver("true_positive", 0.50) is True    # low confidence
    assert requires_second_approver("true_positive", 0.90) is False
