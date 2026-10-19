"""POST /api/engagements/{id}/milestones: Project Management publishes a ProServ
engagement's client-visible milestones; the portal shows them and a newly reached
one is bound into the client's signed chain once."""
from app import auth, evidence
from app.db import Client, DeliverableEvent, Engagement, SessionLocal, User, client_event_records


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}", "X-Vendetta-Actor": "project-management"}


def _eng():
    db = SessionLocal()
    c = Client(name="Bermuda Monetary Authority", portal_enabled=True, portal_domains="bma.example")
    db.add(c); db.flush()
    e = Engagement(client_id=c.id, name="AI tabletop", kind="tabletop", status="active", published=True)
    db.add(e); db.commit()
    return c, e


def _body(status="planned"):
    return {"source_module": "project-management", "milestones": [
        {"key": "m1", "title": "Scenario approved", "status": status, "due_on": "2026-11-02",
         "completed_on": "2026-11-01" if status == "done" else None}]}


def test_publish_show_and_chain_once(client):
    c, e = _eng()
    r = client.post(f"/api/engagements/{e.id}/milestones", json=_body(), headers=_bearer())
    assert r.status_code == 200 and r.json()["milestones"] == 1
    assert client.post(f"/api/engagements/{e.id}/milestones", json=_body("done"), headers=_bearer()).json()[
        "new_completions"] == 1
    assert client.post(f"/api/engagements/{e.id}/milestones", json=_body("done"), headers=_bearer()).json()[
        "new_completions"] == 0
    db = SessionLocal()
    assert db.query(DeliverableEvent).filter_by(client_id=c.id, kind="milestone_reached").count() == 1
    assert evidence.verify_chain(client_event_records(db, c.id))["ok"]
    db.add(User(email="ops@bma.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("ops@bma.example"))
    page = client.get(f"/portal/engagements/{e.id}").text
    assert "Scenario approved" in page and "reached 2026-11-01" in page


def test_needs_token_and_engagement(client):
    _c, e = _eng()
    assert client.post(f"/api/engagements/{e.id}/milestones", json=_body()).status_code == 401
    assert client.post("/api/engagements/nope/milestones", json=_body(), headers=_bearer()).status_code == 404
