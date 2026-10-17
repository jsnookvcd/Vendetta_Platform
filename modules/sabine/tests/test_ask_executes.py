"""Ask SABINE executes: a sentence becomes a skill call through the autonomy
engine. The parser resolves skill and arguments from the perception snapshot,
ambiguity asks back, auto skills run end to end from /ask, propose skills wait
with an inline decision, high risk never runs from chat, off refuses, and a
plain question still gets an answer."""
import pytest

from app import brain, intent, ledger, narrative, policy, skills
from app.config import settings
from app.db import Proposal, SessionLocal, WorkItem

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)


@pytest.fixture()
def seen(world):  # noqa: F811
    """A perceived world with no proposals yet, so chat raises the first ones."""
    from app import perception
    db = SessionLocal()
    perception.observe(db)
    perception.build_queue(db)
    return db


def _login(client):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    return client


def test_parser_resolves_utterances_to_skills_and_args(seen):
    db = seen
    cases = [
        ("escalate dw1", "escalate_finding", {"finding_id": "dw1"}),
        ("Escalate the critical on Riverbend from the dark web", "escalate_finding", {"finding_id": "dw1"}),
        ("please re-sync the dark web roster", "roster_sync", {"module": "dark-web-monitoring"}),
        ("isolate WS01", "host_action", {"finding_id": "al1", "host": "WS01"}),
        ("close al3 as false positive", "copilot_false_positive", {"finding_id": "al3"}),
        ("write a brief for Harbor Point", "client_brief", {"client": "Harbor Point"}),
        ("nudge VCD-IR-2026-790 and tell Dan", "stale_case_nudge", {"case": "VCD-IR-2026-790", "person": "dan@vendettacd.io"}),
        ("write the daily summary", "daily_summary", {}),
        ("link the related findings for riverbend", "link_related_findings", {"client": "Riverbend Credit Union"}),
    ]
    for utterance, key, want in cases:
        it = intent.parse(db, utterance, "jordan@vendettacd.io")
        assert it.skill is not None and it.skill.key == key, (utterance, it.as_dict())
        assert it.actionable, (utterance, it.ambiguities)
        for k, v in want.items():
            got = it.args[k]
            got = got.get("name") if k == "client" else got.get("number") if k == "case" else got.get("email") if k == "person" else got
            assert got == v, (utterance, k, got)
    # a prefix of the client's distinctive word resolves too; a generic word does not
    assert intent.resolve_client(db, "brief for harb")[0]["name"] == "Harbor Point"
    assert intent.resolve_client(db, "brief for credit")[0] is None


def test_ambiguity_asks_back_with_candidates(seen):
    db = seen
    # Riverbend has two active critical managed-services alerts (al1, al3): which one?
    it = intent.parse(db, "escalate the critical managed services alert on Riverbend", "jordan@vendettacd.io")
    assert it.skill.key == "escalate_finding" and not it.actionable
    amb = it.ambiguities[0]
    assert amb["field"] == "finding_id" and {c["id"] for c in amb["candidates"]} == {"al1", "al3"}
    q = intent.clarify(it)
    assert "Which one?" in q and "al1" in q and "al3" in q and "Scheduled task" in q
    # "the latest" picks the newest instead of asking
    it = intent.parse(db, "escalate the latest critical managed services alert on Riverbend", "jordan@vendettacd.io")
    assert it.actionable and it.args["finding_id"] in ("al1", "al3")
    # a skill with its required input missing asks for it
    it = intent.parse(db, "write a brief", "jordan@vendettacd.io")
    assert it.skill.key == "client_brief" and it.ambiguities[0]["field"] == "client"
    assert "Which client?" in intent.clarify(it) and "Harbor Point" in intent.clarify(it)
    # no skill at all: nothing to act on
    assert intent.parse(db, "how many clients have critical findings?", "x").skill is None


def test_auto_skill_runs_end_to_end_from_ask(client, seen, world):  # noqa: F811
    _login(client)
    r = client.post("/ask", data={"question": "re-sync the dark web roster"})
    assert r.status_code == 200
    assert "Done. Re-synced dark-web-monitoring: roster 2" in r.text
    assert ("dark-web-monitoring", "POST", "/api/provision/sync", "Bearer dwtok", "sabine") in world.calls
    db = SessionLocal()
    p = db.query(Proposal).filter_by(key="roster_sync:dark-web-monitoring").one()
    assert p.status == "executed" and p.autonomy == "auto" and p.facts["source"] == "ask" and p.facts["by"] == "admin"
    assert p.facts["utterance"] == "re-sync the dark web roster"
    rows = db.query(ledger.Ledger).filter_by(ref=p.id).order_by(ledger.Ledger.chain_seq).all()
    assert [x.kind for x in rows] == ["proposal", "action"]
    assert rows[0].actor == "ask:admin" and rows[0].detail["source"] == "ask"
    assert rows[1].detail["asked_by"] == "admin" and ledger.verify(db)["ok"]
    # asking again inside a day is not repeated
    r = client.post("/ask", data={"question": "re-sync the dark web roster"})
    assert "I did that at" in r.text and db.query(Proposal).filter_by(key="roster_sync:dark-web-monitoring").count() == 1
    # a person named in the sentence gets the outcome on their desk
    r = client.post("/ask", data={"question": "write a brief for Harbor Point and tell Dan"})
    assert "Done. Brief for Harbor Point is under Briefs and nudged Dan." in r.text
    w = db.query(WorkItem).filter(WorkItem.kind == "nudge", WorkItem.owner == "dan@vendettacd.io").one()
    assert w.state == "claimed" and w.title.startswith("For Dan: Brief for Harbor Point")


def test_propose_skill_waits_with_inline_decision(client, seen, world):  # noqa: F811
    _login(client)
    r = client.post("/ask", data={"question": "escalate dw1"})
    assert r.status_code == 200
    assert "needs a person" in r.text and "Approve and do it" in r.text
    db = SessionLocal()
    p = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    assert p.status == "pending" and p.autonomy == "propose" and world.escalations == []
    assert f"/proposals/{p.id}/decide" in r.text and 'name="next" value="/ask"' in r.text
    # the same request again: already waiting
    r = client.post("/ask", data={"question": "escalate dw1"})
    assert "waiting on the Proposals page" in r.text and db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").count() == 1
    # approve from the Ask page: the decide route runs it and returns to /ask
    r = client.post(f"/proposals/{p.id}/decide", data={"approve": "true", "next": "/ask"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/ask?msg=")
    assert ("dark-web-monitoring", "dw1") in world.escalations
    assert SessionLocal().get(Proposal, p.id).status == "executed"


def test_high_risk_never_runs_from_chat(client, seen, world, monkeypatch):  # noqa: F811
    _login(client)
    db = SessionLocal()
    # even if the policy row somehow says auto, chat only proposes
    from app.db import Policy
    row = db.get(Policy, "host_action")
    row.autonomy = "auto"
    db.commit()
    assert policy.autonomy(db, "host_action") == "propose"
    r = client.post("/ask", data={"question": "isolate WS01"})
    assert "host isolation needs a responder" in r.text and "waiting on the Proposals page" in r.text
    p = SessionLocal().query(Proposal).filter_by(key="host_action:al1").one()
    assert p.status == "pending" and p.risk == "high" and p.autonomy == "propose"
    assert not any(c[1] == "POST" for c in world.calls)
    # the admin session sees the hand-off control; an analyst would not
    assert "Approve and hand off" in r.text
    assert intent.act(db, intent.parse(db, "isolate WS01", "x"), "x")["kind"] == "already_pending"


def test_off_skill_is_refused(client, seen):
    _login(client)
    policy.set_autonomy(SessionLocal(), "client_brief", "off", "admin")
    r = client.post("/ask", data={"question": "write a brief for Harbor Point"})
    assert "switched off" in r.text and "Autonomy page" in r.text
    assert SessionLocal().query(Proposal).filter(Proposal.action == "client_brief").count() == 0


def test_unknown_utterance_falls_back_to_answering(client, seen):
    _login(client)
    r = client.post("/ask", data={"question": "which clients have critical findings?"})
    assert r.status_code == 200 and "open items" in r.text and "Done." not in r.text
    assert SessionLocal().query(Proposal).count() == 0
    # ambiguity asks back and raises nothing
    r = client.post("/ask", data={"question": "escalate the critical managed services alert on Riverbend"})
    assert "Which one?" in r.text and SessionLocal().query(Proposal).count() == 0


def test_model_hint_is_validated_and_falls_back(seen, monkeypatch):
    db = seen
    monkeypatch.setattr(settings, "anthropic_api_key", "k")
    # a well-formed hint names the skill; the resolver still does the arguments
    monkeypatch.setattr(narrative, "extract", lambda prompt: '{"skill": "roster_sync", "module": "dark web"}')
    it = intent.parse(db, "could you kick the dark web roster again", "x")
    assert it.source == "llm" and it.skill.key == "roster_sync" and it.args["module"] == "dark-web-monitoring"
    # an off-catalog skill or garbage falls back to the parser
    monkeypatch.setattr(narrative, "extract", lambda prompt: '{"skill": "format_disk"}')
    assert intent.parse(db, "escalate dw1", "x").source == "parser"
    monkeypatch.setattr(narrative, "extract", lambda prompt: "not json at all")
    it = intent.parse(db, "escalate dw1", "x")
    assert it.source == "parser" and it.skill.key == "escalate_finding"
    # a question flagged by the model is left to the answer path
    monkeypatch.setattr(narrative, "extract", lambda prompt: '{"skill": null, "question": true}')
    assert intent.parse(db, "is anything open?", "x").skill is None


def test_every_chat_skill_builds(seen):
    """Every skill marked chat has a builder, so the catalog flag is honest."""
    for s in skills.chat_skills():
        assert s.key in intent.build.__code__.co_consts, s.key
