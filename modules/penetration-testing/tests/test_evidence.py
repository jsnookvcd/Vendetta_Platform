"""The per-client finding-event chain for pentest engagements."""
from app import auth, evidence
from app.db import Client, FindingEvent, SessionLocal, User, client_event_records


def _client(name="Acme", pid="plat-ac"):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=True, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _engagement(admin, cid, name="External Test"):
    r = admin.post(f"/clients/{cid}/engagements", data={"name": name, "kind": "external"}, follow_redirects=False)
    return r.headers["location"].split("/engagements/")[1]


def _finding(admin, eid, title="SQLi", severity="high", cvss="7.5"):
    r = admin.post(f"/engagements/{eid}/findings",
                   data={"title": title, "asset": "/login", "cvss": cvss, "severity": severity},
                   follow_redirects=False)
    return r.headers["location"].split("/findings/")[1]


def test_finding_lifecycle_events_chain(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    fid = _finding(admin, eid, "SQLi", "critical", "9.1")
    admin.post(f"/findings/{fid}/edit", data={"status": "remediating", "severity": "critical", "cvss": "9.1"})
    admin.post(f"/findings/{fid}/steps", data={"text": "Parameterize the query"})
    admin.post(f"/engagements/{eid}/edit", data={"status": "reporting", "published": "true"})
    recs = client_event_records(SessionLocal(), c.id)
    kinds = [r["fields"]["kind"] for r in recs]
    assert "created" in kinds and "status" in kinds and "step_added" in kinds and "published" in kinds
    assert evidence.verify_chain(recs)["ok"]
    assert [r["fields"]["chain_seq"] for r in recs] == list(range(1, len(recs) + 1))


def test_tampering_detected(admin):
    import sqlalchemy as sa
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "XSS", "high", "7.0")
    db = SessionLocal()
    e = db.execute(sa.select(FindingEvent).where(FindingEvent.client_id == c.id)).scalars().first()
    e.actor = "someone-else"
    db.commit()
    assert evidence.verify_chain(client_event_records(SessionLocal(), c.id))["ok"] is False


def test_proof_endpoints(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    fid = _finding(admin, eid, "Thing", "medium", "5.0")
    admin.post(f"/engagements/{eid}/edit", data={"status": "reporting", "published": "true"})
    v = admin.get(f"/clients/{c.id}/evidence/verify")
    assert v.status_code == 200 and v.json()["ok"] is True
    p = admin.get(f"/clients/{c.id}/evidence/proof.json").json()
    assert p["verification"]["ok"] and p["entry_count"] >= 2
    db = SessionLocal(); db.add(User(email="it@acme.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    assert client.get("/portal/evidence/proof.json").json()["verification"]["ok"] is True
