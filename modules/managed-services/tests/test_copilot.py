"""The triage copilot on alerts: a proposal is computed when sync first sees an alert
and signed into the client's chain, the finding API exposes it, a human decision is
signed with its approver, and closing on the copilot's verdict is held to the
module's two-person rule."""
from app import auth, copilot, evidence
from app.config import settings
from app.db import ActionLog, Alert, SessionLocal, client_chain_records

from test_app import FakeS1, _client_with_s1
from test_rbac import _as


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def _synced_alert():
    fake = FakeS1()
    db, c = _client_with_s1(fake)
    from app.sync import sync_client_tool
    sync_client_tool(db, c, "sentinelone")
    return fake, SessionLocal().query(Alert).one()


def _chain(client_id):
    recs = client_chain_records(SessionLocal(), client_id)
    assert evidence.verify_chain(recs)["ok"]
    return recs


def test_proposal_computed_on_first_upsert_and_signed(fresh_db):
    fake, a = _synced_alert()
    cp = a.copilot
    assert cp and cp["verdict"] == "true_positive" and cp["model"] == "rules-v1"
    assert 0.0 < cp["confidence"] <= 1.0 and "critical severity" in cp["rationale"]
    assert cp["requires_approval"] is False and cp["created_at"]
    recs = _chain(a.client_id)
    proposed = [r for r in recs if r["fields"]["action"] == "triage_proposed"]
    assert len(proposed) == 1
    assert proposed[0]["fields"]["actor"] == "copilot:rules-v1"
    assert proposed[0]["fields"]["payload"]["verdict"] == "true_positive"
    # a second sync of the same alert does not re-propose
    from app.sync import sync_client_tool
    db = SessionLocal()
    sync_client_tool(db, db.query(Alert).one().client, "sentinelone")
    assert len([r for r in _chain(a.client_id) if r["fields"]["action"] == "triage_proposed"]) == 1


def test_api_exposes_the_proposal_and_recomputes_on_demand(admin):
    fake, a = _synced_alert()
    rows = admin.get("/api/findings", headers=_bearer()).json()
    f = next(r for r in rows if r["id"] == a.id)
    assert f["copilot"]["verdict"] == "true_positive" and f["copilot"]["decision"] is None
    assert set(f["copilot"]) >= {"verdict", "confidence", "rationale", "model", "requires_approval", "created_at"}
    r = admin.post(f"/api/alerts/{a.id}/copilot", headers=_bearer())
    assert r.status_code == 200 and r.json()["copilot"]["verdict"] == "true_positive"
    assert len([x for x in _chain(a.client_id) if x["fields"]["action"] == "triage_proposed"]) == 2
    page = admin.get(f"/alerts/{a.id}").text
    assert "Copilot: <b>True positive</b>" in page and "because" in page
    assert "cp-true_positive" in admin.get("/alerts").text


def test_accepting_true_positive_acknowledges_and_signs_the_decision(client):
    fake, a = _synced_alert()
    _as(client, "analyst@vendettacd.io", can_act=True, can_approve=False)
    r = client.post(f"/alerts/{a.id}/copilot/decide", data={"decision": "accept"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    a = SessionLocal().get(Alert, a.id)
    assert a.status == "acknowledged" and a.acknowledged_at is not None
    assert a.copilot["decision"]["decision"] == "accepted" and a.copilot["decision"]["analyst"] == "analyst@vendettacd.io"
    decided = [x for x in _chain(a.client_id) if x["fields"]["action"] == "triage_decided"]
    assert decided and decided[0]["fields"]["actor"] == "analyst@vendettacd.io"
    assert decided[0]["fields"]["payload"]["proposed_verdict"] == "true_positive"


def test_closing_on_copilot_verdict_enforces_two_person_rule(client, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    _as(client, "lead@vendettacd.io", can_act=False, can_approve=True)
    _as(client, "analyst@vendettacd.io", can_act=True, can_approve=False)
    # overriding to false positive closes the alert: without an approver it is blocked
    r = client.post(f"/alerts/{a.id}/copilot/decide",
                    data={"decision": "override", "verdict": "false_positive"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "approval" in r.headers["location"]
    assert SessionLocal().get(Alert, a.id).status == "open"
    blocked = SessionLocal().query(ActionLog).filter_by(alert_id=a.id, result="blocked").one()
    assert blocked.action == "triage_decided"
    # a named approver who can approve lets it through, and is inside the signed record
    r = client.post(f"/alerts/{a.id}/copilot/decide",
                    data={"decision": "override", "verdict": "false_positive", "approver": "lead@vendettacd.io",
                          "note": "known admin tool"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    a = SessionLocal().get(Alert, a.id)
    assert a.status == "resolved" and a.contained_at is not None
    assert a.copilot["decision"] == {**a.copilot["decision"], "decision": "overridden",
                                     "final_verdict": "false_positive", "approver": "lead@vendettacd.io"}
    decided = [x for x in _chain(a.client_id) if x["fields"]["action"] == "triage_decided" and x["fields"]["result"] == "ok"]
    assert decided[-1]["fields"]["approver"] == "lead@vendettacd.io"
    assert decided[-1]["fields"]["payload"]["final_verdict"] == "false_positive"
    assert decided[-1]["fields"]["payload"]["required_approval"] is False  # the proposal itself was confident
    f = next(r for r in client.get("/api/findings?status=all", headers=_bearer()).json() if r["id"] == a.id)
    assert f["copilot"]["decision"]["approver"] == "lead@vendettacd.io"


def test_strict_mode_forbids_self_approval_of_a_close(admin, monkeypatch):
    monkeypatch.setattr(settings, "require_second_approver", True)
    fake, a = _synced_alert()
    r = admin.post(f"/alerts/{a.id}/copilot/decide",
                   data={"decision": "override", "verdict": "benign_expected", "approver": "admin"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().get(Alert, a.id).status == "open"


def test_prior_human_verdict_shapes_the_next_proposal(admin):
    """A human's false-positive call on an alert becomes the strongest signal for the
    next alert with the same client, tool and signature, which then arrives proposed
    as a false positive that requires approval."""
    fake, a = _synced_alert()
    admin.post(f"/alerts/{a.id}/copilot/decide", data={"decision": "override", "verdict": "false_positive"})
    assert SessionLocal().get(Alert, a.id).status == "resolved"  # admin self-approves by default
    db = SessionLocal()
    c = db.get(Alert, a.id).client
    db.add(Alert(client_id=c.id, tool="sentinelone", external_id="t10", kind="threat", severity="critical",
                 title="Ransomware behavior blocked", detail="pre-execution · WS02"))
    db.commit()
    b = db.query(Alert).filter_by(external_id="t10").one()
    p = copilot.propose(db, b)
    db.commit()
    assert p.verdict == "false_positive" and p.requires_approval is True
    assert "previously dispositioned" in p.rationale


def test_tampering_with_a_signed_proposal_is_detected(fresh_db):
    import sqlalchemy as sa
    fake, a = _synced_alert()
    db = SessionLocal()
    row = db.execute(sa.select(ActionLog).where(ActionLog.alert_id == a.id, ActionLog.action == "triage_proposed")).scalar_one()
    row.payload = {**row.payload, "verdict": "false_positive"}
    db.commit()
    res = evidence.verify_chain(client_chain_records(SessionLocal(), a.client_id))
    assert res["ok"] is False
