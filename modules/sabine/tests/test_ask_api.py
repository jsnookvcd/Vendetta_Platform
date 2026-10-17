"""POST /api/ask and person-attributed decisions, for chat bridges. The Slack
responder holds SABINE's bearer token and names the member of staff it acts for;
the record carries that person, a high-risk skill never runs from here, and the
bridge cannot decide a high-risk proposal."""
import pytest

from app import auth, perception
from app.db import Ledger, Proposal, SessionLocal

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)

PERSON = "dan@vendettacd.io"


def _h(person: str = PERSON):
    h = {"Authorization": f"Bearer {auth.api_token()}", "X-Vendetta-Actor": "slack"}
    if person:
        h["X-Vendetta-On-Behalf-Of"] = person
    return h


@pytest.fixture()
def seen(world, client):  # noqa: F811
    db = SessionLocal()
    perception.observe(db)
    perception.build_queue(db)
    return client


def test_plain_question_is_answered_and_recorded_against_the_person(seen):
    r = seen.post("/api/ask", headers=_h(), json={"question": "what is open for Riverbend?"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["reply"] and out["outcome"] == "" and out["proposal"] is None
    row = SessionLocal().query(Ledger).filter(Ledger.kind == "observation").order_by(Ledger.id.desc()).first()
    assert row.actor == f"{PERSON} via slack"


def test_request_becomes_a_proposal_and_high_risk_never_runs(seen):
    out = seen.post("/api/ask", headers=_h(), json={"question": "isolate WS01"}).json()
    assert out["outcome"] == "high" and out["proposal"]["risk"] == "high" and out["proposal"]["status"] == "pending"
    pid = out["proposal"]["id"]
    r = seen.post(f"/api/proposals/{pid}/decide", headers=_h(), json={"approve": True})
    assert r.status_code == 403
    assert SessionLocal().get(Proposal, pid).status == "pending"


def test_decision_through_the_bridge_names_the_person(seen):
    out = seen.post("/api/ask", headers=_h(), json={"question": "escalate dw1"}).json()
    p = out["proposal"]
    assert p is not None and p["risk"] != "high"
    assert p["status"] == "pending"  # escalate_finding defaults to propose
    r = seen.post(f"/api/proposals/{p['id']}/decide", headers=_h(), json={"approve": False, "note": "dupe"})
    assert r.status_code == 200, r.text
    assert SessionLocal().get(Proposal, p["id"]).decided_by == f"{PERSON} via slack"


def test_empty_question_and_no_token(seen):
    assert seen.post("/api/ask", headers=_h(), json={"question": "  "}).status_code == 400
    r = seen.post("/api/ask", headers={"X-Vendetta-On-Behalf-Of": PERSON}, json={"question": "hi"})
    assert r.status_code in (401, 403)
