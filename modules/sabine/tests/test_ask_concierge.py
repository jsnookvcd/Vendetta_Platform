"""Ask SABINE for the new skills: page on-call, draft the posture review, draft an
email to a client, suggest a suppression. Each runs under the autonomy policy,
including the client's own override."""
import pytest

from app import intent, policy
from app.db import Proposal, SessionLocal


@pytest.fixture()
def seen(world):
    from app import perception
    db = SessionLocal()
    perception.observe(db)
    perception.build_queue(db)
    return db


def _login(client):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    return client


def test_parser_knows_the_new_skills(seen):
    cases = [("page on-call for i1", "page_oncall", "i1"),
             ("draft the posture review for Riverbend", "posture_review", "Riverbend Credit Union"),
             ("draft an email to Harbor Point", "client_outreach", "Harbor Point"),
             ("suggest a suppression for i1", "suggest_suppression", "i1")]
    for utterance, key, want in cases:
        it = intent.parse(seen, utterance, "jordan@vendettacd.io")
        assert it.skill is not None and it.skill.key == key and it.actionable, (utterance, it.as_dict())
        got = it.args.get("finding_id") or it.args["client"]["name"]
        assert got == want, utterance


def test_ask_pages_on_call_and_drafts_the_review(client, seen, world):
    _login(client)
    r = client.post("/ask", data={"question": "page on-call for i1"})
    assert "Done. Paged the on-call responder for i1 on Riverbend Credit Union: paged via teams" in r.text
    assert world.pages[-1]["source_ref"] == "mdr:i1" and world.pages[-1]["link"] == "https://mdr.example/investigations/i1"
    r = client.post("/ask", data={"question": "draft the posture review for Riverbend"})
    assert "The posture review for Riverbend Credit Union is a draft on the platform" in r.text
    item = world.communications["plat-rb"][0]
    assert item["kind"] == "posture_review" and item["status"] == "draft" and "Harbor Point" not in item["body_md"]
    r = client.post("/ask", data={"question": "draft an email to Harbor Point"})
    assert "The email to Harbor Point is a draft on the platform" in r.text
    out = world.communications["plat-hp"][0]
    assert out["kind"] == "outreach" and "Your Vendetta team" in out["body_md"]


def test_ask_suppression_waits_for_a_person(client, seen, world):
    _login(client)
    r = client.post("/ask", data={"question": "suggest a suppression for i1"})
    assert "needs a person" in r.text
    p = SessionLocal().query(Proposal).filter_by(action="suggest_suppression").one()
    assert p.status == "pending" and p.target["platform_client_id"] == "plat-rb" and not world.suppressions


def test_ask_honours_the_client_override(client, seen, world):
    _login(client)
    policy.set_client_autonomy(SessionLocal(), "plat-rb", "posture_review", "off", "admin", "Riverbend Credit Union")
    r = client.post("/ask", data={"question": "draft the posture review for Riverbend"})
    assert "switched off" in r.text and not world.communications["plat-rb"]
    policy.set_client_autonomy(SessionLocal(), "plat-hp", "posture_review", "propose", "admin", "Harbor Point")
    r = client.post("/ask", data={"question": "draft the posture review for Harbor Point"})
    assert "needs a person" in r.text and not world.communications["plat-hp"]
