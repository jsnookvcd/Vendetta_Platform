"""Engagements, deliverables, the acceptance sign-off loop, portal and API."""
from app import auth
from app.db import Client, Deliverable, Engagement, SessionLocal, User


def _client(name="Acme Corp", pid="plat-acme", portal=True):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=portal, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _engagement(admin, cid, name="vCISO Retainer", kind="vciso"):
    r = admin.post(f"/clients/{cid}/engagements",
                   data={"name": name, "kind": kind, "cadence": "monthly"}, follow_redirects=False)
    return r.headers["location"].split("/engagements/")[1]


def _deliverable(admin, eid, title="ISP v1", kind="policy"):
    admin.post(f"/engagements/{eid}/deliverables",
               data={"title": title, "kind": kind, "description": "d", "artifact_ref": "https://x/y"},
               follow_redirects=False)
    db = SessionLocal()
    return db.query(Deliverable).filter_by(engagement_id=eid, title=title).one().id


def _as_client(client, email, c, execs=""):
    db = SessionLocal()
    if execs:
        cc = db.get(Client, c.id); cc.executive_emails = execs; db.commit()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_engagement_and_deliverables_and_counts(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    _deliverable(admin, eid, "ISP v1", "policy")
    _deliverable(admin, eid, "IR Playbook", "playbook")
    db = SessionLocal()
    e = db.get(Engagement, eid)
    counts = e.counts()
    assert counts["total"] == 2 and counts["planned"] == 2 and e.progress() == 0
    assert db.query(Deliverable).filter_by(engagement_id=eid).count() == 2


def test_deliver_then_client_accepts_signoff(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid)
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "published": "true"})
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": "ISP v1"})
    _as_client(client, "it@acme.example", c)
    client.post(f"/portal/deliverables/{did}/accept", follow_redirects=False)
    d = SessionLocal().get(Deliverable, did)
    assert d.status == "accepted" and d.accepted_by == "it@acme.example" and d.accepted_at is not None


def test_staff_cannot_set_accepted(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid)
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": "ISP v1"})
    admin.post(f"/deliverables/{did}/edit", data={"status": "accepted", "kind": "policy", "title": "ISP v1"})
    d = SessionLocal().get(Deliverable, did)
    assert d.status == "delivered" and d.accepted_by == ""


def test_cannot_delete_accepted_deliverable(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid)
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "published": "true"})
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": "ISP v1"})
    _as_client(client, "it@acme.example", c)
    client.post(f"/portal/deliverables/{did}/accept", follow_redirects=False)
    # admin and client share one TestClient; restore the staff session before deleting.
    admin.cookies.set(auth.COOKIE, auth.make_session("admin"))
    r = admin.post(f"/deliverables/{did}/delete", follow_redirects=False)
    assert "cannot+delete" in r.headers["location"]
    assert SessionLocal().get(Deliverable, did) is not None


def test_portal_shows_only_published(admin, client):
    c = _client()
    pub = _engagement(admin, c.id, name="Shared vCISO")
    admin.post(f"/engagements/{pub}/edit", data={"status": "active", "published": "true"})
    _engagement(admin, c.id, name="Hidden Project", kind="implementation")  # unpublished
    _as_client(client, "it@acme.example", c)
    page = client.get("/portal").text
    assert "Shared vCISO" in page and "Hidden Project" not in page


def test_executive_view_sees_summary(admin, client):
    c = _client()
    eid = _engagement(admin, c.id, name="Board advisory", kind="advisory")
    admin.post(f"/engagements/{eid}/edit",
               data={"status": "active", "published": "true", "summary": "Executive-only narrative"})
    _as_client(client, "ceo@acme.example", c, execs="ceo@acme.example")
    page = client.get(f"/portal/engagements/{eid}").text
    assert "Executive-only narrative" in page and "Executive view" in page


def test_api_module_shape(admin):
    out = admin.get("/api/module", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out["module"] == "professional-services" and "vciso" in out["engagement_types"]
    assert "readiness" in out


def test_api_engagements_lists_open_with_deliverables_and_dates(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    did = _deliverable(admin, eid)
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": "ISP v1"})
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "starts_on": "2026-01-05", "ends_on": "2026-03-31"})
    closed = _engagement(admin, c.id, name="Done project", kind="implementation")
    admin.post(f"/engagements/{closed}/edit", data={"status": "closed"})
    bearer = {"Authorization": f"Bearer {auth.api_token()}"}
    rows = admin.get("/api/engagements", headers=bearer).json()
    assert [r["id"] for r in rows] == [eid]
    e = rows[0]
    assert e["subject"]["platform_client_id"] == "plat-acme" and e["subject"]["client"] == "Acme Corp"
    assert e["status"] == "active" and e["open"] is True and e["overdue"] is True
    assert e["starts_on"].startswith("2026-01-05") and e["ends_on"].startswith("2026-03-31")
    assert e["deliverables"][0]["status"] == "delivered" and e["deliverables"][0]["delivered_at"]
    assert len(admin.get("/api/engagements?status=all", headers=bearer).json()) == 2
    assert [r["id"] for r in admin.get("/api/engagements?status=closed", headers=bearer).json()] == [closed]
    assert admin.get("/api/engagements?platform_client_id=plat-acme", headers=bearer).json()[0]["id"] == eid
    assert admin.get("/api/engagements?platform_client_id=nope", headers=bearer).json() == []
    assert admin.get("/api/engagements?status=bogus", headers=bearer).status_code == 400
    # a blank planned end clears it and the engagement is no longer overdue
    admin.post(f"/engagements/{eid}/edit", data={"status": "active", "ends_on": ""})
    assert admin.get("/api/engagements", headers=bearer).json()[0]["overdue"] is False
