"""The per-client deliverable sign-off chain for professional-services engagements."""
from app import auth, evidence
from app.db import Client, Deliverable, DeliverableEvent, SessionLocal, User, client_event_records


def _client(name="Acme", pid="plat-ac"):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=True, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _engagement(admin, cid, name="vCISO Retainer"):
    r = admin.post(f"/clients/{cid}/engagements",
                   data={"name": name, "kind": "vciso", "cadence": "monthly"}, follow_redirects=False)
    return r.headers["location"].split("/engagements/")[1]


def _deliverable(admin, eid, title="ISP v1"):
    admin.post(f"/engagements/{eid}/deliverables",
               data={"title": title, "kind": "policy"}, follow_redirects=False)
    return SessionLocal().query(Deliverable).filter_by(engagement_id=eid, title=title).one().id


def _as_client(client, email, c):
    db = SessionLocal()
    db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_deliverable_lifecycle_events_chain(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid, "ISP v1")
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "published": "true"})
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": "ISP v1"})
    _as_client(client, "it@acme.example", c)
    client.post(f"/portal/deliverables/{did}/accept", follow_redirects=False)
    recs = client_event_records(SessionLocal(), c.id)
    kinds = [r["fields"]["kind"] for r in recs]
    assert "engagement_opened" in kinds and "deliverable_created" in kinds
    assert "engagement_published" in kinds and "deliverable_accepted" in kinds
    assert evidence.verify_chain(recs)["ok"]
    assert [r["fields"]["chain_seq"] for r in recs] == list(range(1, len(recs) + 1))


def test_tampering_detected(admin):
    import sqlalchemy as sa
    c = _client()
    eid = _engagement(admin, c.id)
    _deliverable(admin, eid, "XSS Fix Plan")
    db = SessionLocal()
    e = db.execute(sa.select(DeliverableEvent).where(DeliverableEvent.client_id == c.id)).scalars().first()
    e.actor = "someone-else"
    db.commit()
    assert evidence.verify_chain(client_event_records(SessionLocal(), c.id))["ok"] is False


def test_proof_endpoints(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid, "Thing")
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "published": "true"})
    v = admin.get(f"/clients/{c.id}/evidence/verify")
    assert v.status_code == 200 and v.json()["ok"] is True
    p = admin.get(f"/clients/{c.id}/evidence/proof.json").json()
    assert p["verification"]["ok"] and p["entry_count"] >= 2
    assert p["document"] == "Vendetta Cyber Defense deliverable sign-off proof"
    _as_client(client, "it@acme.example", c)
    assert client.get("/portal/evidence/proof.json").json()["verification"]["ok"] is True
