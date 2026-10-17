"""The detection engine is a pure function; these tests need no database."""
import datetime as dt

import pytest

from app import attack, engine as eng
from app.rules_seed import STARTER_RULES

NOW = dt.datetime(2026, 10, 17, 12, 0, tzinfo=dt.timezone.utc)


def sig(sid, *, pid="p1", tool="sentinelone", typ="threat", sev="high", title="Ransomware behavior detected",
        host="WS01", mins_ago=5, client="Acme"):
    return eng.Signal(sid, pid, client, tool, typ, sev, title, host, NOW - dt.timedelta(minutes=mins_ago))


RANSOM = eng.Rule(key="ransom", name="Ransomware behavior", severity="critical", tools=("sentinelone",),
                  title_any=("ransom",), mitre=("T1486",), response="isolate_host")
BURST = eng.Rule(key="burst", name="Burst", severity="high", min_severity="medium", group_by="host",
                 window_minutes=30, threshold=3)


def run(signals, rules, **kw):
    return eng.evaluate(signals, rules, now=NOW, **kw)


def test_single_signal_rule_opens_with_rule_fields():
    plan = run([sig("a")], [RANSOM])
    assert len(plan.opens) == 1
    o = plan.opens[0]
    assert (o.rule_key, o.platform_client_id, o.group_key, o.severity) == ("ransom", "p1", "ws01", "critical")
    assert o.signal_ids == ["a"] and o.mitre == ["T1486"] and o.response == "isolate_host"
    assert o.title == "Ransomware behavior on WS01" and o.host == "WS01"
    assert o.first_signal_at == NOW - dt.timedelta(minutes=5)


@pytest.mark.parametrize("change", [
    {"tool": "huntress"},                 # tool not listed
    {"title": "Benign installer"},        # no title substring
])
def test_non_matching_signal_does_nothing(change):
    assert run([sig("a", **change)], [RANSOM]).opens == []


def test_title_match_is_case_insensitive_and_types_filter():
    r = eng.Rule(key="b", name="Backup", severity="medium", tools=("acronis",), types=("backup",),
                 title_any=("FAIL",))
    assert run([sig("a", tool="acronis", typ="backup", title="Backup job failed")], [r]).opens
    assert not run([sig("a", tool="acronis", typ="threat", title="Backup job failed")], [r]).opens


def test_min_severity_floor_and_info_counts_as_low():
    r = eng.Rule(key="m", name="M", severity="high", min_severity="medium")
    assert not run([sig("a", sev="low")], [r]).opens
    assert not run([sig("a", sev="info")], [r]).opens
    assert run([sig("a", sev="medium")], [r]).opens


def test_correlation_threshold_inside_window_opens():
    sigs = [sig(f"s{i}", sev="medium", title=f"alert {i}", mins_ago=m) for i, m in enumerate([2, 10, 20])]
    plan = run(sigs, [BURST])
    assert len(plan.opens) == 1 and sorted(plan.opens[0].signal_ids) == ["s0", "s1", "s2"]


def test_correlation_below_threshold_or_outside_window_waits():
    two = [sig("s0", sev="medium", mins_ago=2), sig("s1", sev="medium", mins_ago=10)]
    assert run(two, [BURST]).opens == []
    spread = [sig(f"s{i}", sev="medium", mins_ago=m) for i, m in enumerate([2, 40, 80])]
    assert run(spread, [BURST]).opens == []


def test_correlation_groups_by_host_separately():
    sigs = ([sig(f"a{i}", sev="high", host="WS01", mins_ago=i) for i in range(2)]
            + [sig(f"b{i}", sev="high", host="WS02", mins_ago=i) for i in range(2)])
    assert run(sigs, [BURST]).opens == []  # 2 + 2, never 3 on one host
    sigs.append(sig("a9", sev="high", host="ws01", mins_ago=3))  # host compare ignores case
    plan = run(sigs, [BURST])
    assert len(plan.opens) == 1 and plan.opens[0].group_key == "ws01"


def test_client_grouping_spans_hosts_and_clients_stay_apart():
    r = eng.Rule(key="spray", name="Spray", severity="medium", tools=("entra",), title_any=("failed sign-in",),
                 group_by="client", window_minutes=30, threshold=3)
    sigs = [sig(f"e{i}", tool="entra", title="Failed sign-in", host=f"user{i}", mins_ago=i) for i in range(3)]
    plan = run(sigs, [r])
    assert len(plan.opens) == 1 and plan.opens[0].group_key == "" and plan.opens[0].host == ""
    mixed = sigs[:2] + [sig("x", pid="p2", tool="entra", title="Failed sign-in")]
    assert run(mixed, [r]).opens == []


def test_open_investigation_attaches_instead_of_opening():
    opens = [eng.OpenInvestigation("inv1", "ransom", "p1", "ws01")]
    plan = run([sig("a"), sig("b", mins_ago=1)], [RANSOM], open_investigations=opens)
    assert plan.opens == [] and len(plan.attaches) == 1
    assert plan.attaches[0].investigation_id == "inv1" and plan.attaches[0].signal_ids == ["a", "b"]
    # another host is its own investigation
    plan = run([sig("c", host="WS09")], [RANSOM], open_investigations=opens)
    assert len(plan.opens) == 1 and plan.attaches == []


def test_already_linked_signals_are_not_reconsidered():
    plan = run([sig("a")], [RANSOM], linked={("ransom", "a")})
    assert plan.opens == [] and plan.attaches == []
    # linked under a different rule does not block this one
    assert run([sig("a")], [RANSOM], linked={("other", "a")}).opens


def test_suppression_sets_signal_aside_for_that_client_only():
    sup = eng.Suppression("s1", "p1", tool="sentinelone", title_contains="RANSOM", host="ws01",
                          expires_at=NOW + dt.timedelta(days=1))
    plan = run([sig("a"), sig("b", pid="p2")], [RANSOM], suppressions=[sup])
    assert plan.suppressed == {"a": "s1"}
    assert [o.platform_client_id for o in plan.opens] == ["p2"]


def test_suppression_fields_must_all_match_and_expired_does_not_apply():
    narrow = eng.Suppression("s1", "p1", tool="sentinelone", host="OTHER", expires_at=NOW + dt.timedelta(days=1))
    assert run([sig("a")], [RANSOM], suppressions=[narrow]).opens
    expired = eng.Suppression("s2", "p1", tool="sentinelone", expires_at=NOW - dt.timedelta(minutes=1))
    plan = run([sig("a")], [RANSOM], suppressions=[expired])
    assert plan.opens and not plan.suppressed


def test_empty_suppression_is_never_honored():
    empty = eng.Suppression("s1", "p1", expires_at=NOW + dt.timedelta(days=1))
    assert run([sig("a")], [RANSOM], suppressions=[empty]).opens


def test_linked_signal_matching_new_suppression_is_not_a_hit():
    sup = eng.Suppression("s1", "p1", tool="sentinelone", expires_at=NOW + dt.timedelta(days=1))
    plan = run([sig("a"), sig("b")], [RANSOM], suppressions=[sup], linked={("ransom", "a")})
    assert plan.suppressed == {"b": "s1"} and plan.opens == []


def test_already_suppressed_signal_is_skipped_without_new_hit():
    sup = eng.Suppression("s1", "p1", tool="sentinelone", expires_at=NOW + dt.timedelta(days=1))
    plan = run([sig("a")], [RANSOM], suppressions=[sup], already_suppressed={"a"})
    assert plan.suppressed == {} and plan.opens == []


def test_override_disables_for_one_client():
    ov = [eng.Override("ransom", "p1", disabled=True)]
    plan = run([sig("a"), sig("b", pid="p2")], [RANSOM], overrides=ov)
    assert [o.platform_client_id for o in plan.opens] == ["p2"]


def test_override_changes_severity_for_one_client():
    ov = [eng.Override("ransom", "p1", severity="medium")]
    plan = run([sig("a"), sig("b", pid="p2")], [RANSOM], overrides=ov)
    sev = {o.platform_client_id: o.severity for o in plan.opens}
    assert sev == {"p1": "medium", "p2": "critical"}


def test_disabled_rule_and_signal_without_client():
    off = eng.Rule(key="ransom", name="R", severity="critical", tools=("sentinelone",), title_any=("ransom",),
                   enabled=False)
    assert run([sig("a")], [off]).opens == []
    plan = run([sig("a", pid="")], [RANSOM])
    assert plan.opens == [] and plan.ignored == 1


def test_lookback_keeps_old_signals_from_opening():
    assert run([sig("a", mins_ago=60 * 30)], [RANSOM], lookback_minutes=1440).opens == []
    assert run([sig("a", mins_ago=60 * 30)], [RANSOM], lookback_minutes=60 * 48).opens


def test_threshold_met_edges():
    t0 = NOW
    assert eng.threshold_met([t0, t0 + dt.timedelta(minutes=30)], 2, 30)
    assert not eng.threshold_met([t0, t0 + dt.timedelta(minutes=31)], 2, 30)
    assert eng.threshold_met([t0], 1, 1)
    assert not eng.threshold_met([], 1, 1)


def test_starter_rules_are_sane():
    keys = [r["key"] for r in STARTER_RULES]
    assert len(keys) == len(set(keys)) and 10 <= len(keys) <= 16
    tools_allowed = {"sentinelone", "crowdstrike", "huntress", "acronis", "superops", "entra", "aws"}
    techniques = set()
    for spec in STARTER_RULES:
        r = eng.Rule.from_dict(spec)
        assert set(r.tools) <= tools_allowed
        assert r.severity in ("low", "medium", "high", "critical")
        assert r.response in ("none", "isolate_host", "disable_account", "block_indicator")
        for t in r.mitre:
            assert attack.valid_technique(t) and attack.tactics_for(t), t
            techniques.add(t)
        # every rule narrows by something or correlates
        assert r.tools or r.types or r.title_any or r.threshold > 1
    for must in ("T1486", "T1003", "T1059.001", "T1078", "T1621", "T1114.003", "T1552.005", "T1053.005",
                 "T1021", "T1490"):
        assert must in techniques, must


def test_starter_rules_fire_on_representative_signals():
    rules = [eng.Rule.from_dict(s) for s in STARTER_RULES]
    cases = {
        "ransomware-behavior": sig("1", tool="crowdstrike", title="Ransomware: mass file modification"),
        "credential-dumping": sig("2", tool="sentinelone", title="LSASS memory access by procdump"),
        "suspicious-powershell": sig("3", tool="huntress", title="PowerShell -EncodedCommand download cradle"),
        "risky-sign-in": sig("4", tool="entra", typ="incident", title="Impossible travel for j.doe"),
        "mfa-fatigue": sig("5", tool="entra", typ="incident", title="MFA fatigue: 14 pushes denied"),
        "mailbox-forwarding": sig("6", tool="entra", typ="incident", title="New inbox rule with external forwarding"),
        "cloud-credential-misuse": sig("7", tool="aws", typ="detection",
                                       title="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"),
        "scheduled-task-persistence": sig("8", tool="crowdstrike", sev="medium", title="Suspicious scheduled task created"),
        "lateral-movement": sig("9", tool="sentinelone", title="PsExec lateral movement to FS01"),
        "backup-tampering": sig("10", tool="sentinelone", title="vssadmin delete shadows"),
    }
    for key, s in cases.items():
        fired = {o.rule_key for o in eng.evaluate([s], rules, now=NOW).opens}
        assert key in fired, (key, fired)
