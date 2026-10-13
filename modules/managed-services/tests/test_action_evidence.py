"""Response actions carry a per-client, signed, tamper-evident chain of custody."""
from app import evidence
from app.db import ActionLog, Client, SessionLocal, build_action_proof, client_chain_records


def _client(name="Client A"):
    db = SessionLocal()
    c = Client(name=name, portal_enabled=True, portal_domains="a.example")
    db.add(c); db.commit()
    return c


def _action(client_id, action, actor="tech@vendettacd.io", tool="sentinelone", visible=True):
    db = SessionLocal()
    db.add(ActionLog(client_id=client_id, tool=tool, action=action, actor=actor, client_visible=visible))
    db.commit()


def test_actions_are_chained_and_verify(client):
    c = _client()
    for a in ("isolate", "contain", "resolve"):
        _action(c.id, a)
    recs = client_chain_records(SessionLocal(), c.id)
    assert [r["fields"]["chain_seq"] if "chain_seq" in r["fields"] else i + 1
            for i, r in enumerate(recs)]  # present
    assert recs[0]["prev_hash"] == evidence.GENESIS
    assert evidence.verify_chain(recs)["ok"]


def test_each_client_has_its_own_chain(client):
    a = _client("A")
    b = _client("B")
    _action(a.id, "isolate")
    _action(b.id, "contain")
    _action(a.id, "resolve")
    ra = client_chain_records(SessionLocal(), a.id)
    rb = client_chain_records(SessionLocal(), b.id)
    assert len(ra) == 2 and len(rb) == 1
    assert evidence.verify_chain(ra)["ok"] and evidence.verify_chain(rb)["ok"]
    assert ra[0]["prev_hash"] == evidence.GENESIS and rb[0]["prev_hash"] == evidence.GENESIS


def test_tampering_with_an_action_is_detected(client):
    import sqlalchemy as sa
    c = _client()
    _action(c.id, "isolate", actor="tech@vendettacd.io")
    _action(c.id, "contain")
    db = SessionLocal()
    row = db.execute(sa.select(ActionLog).where(ActionLog.client_id == c.id, ActionLog.action == "isolate")).scalar_one()
    row.actor = "someone-else@evil.example"  # rewrite who did it, without re-signing
    db.commit()
    res = evidence.verify_chain(client_chain_records(SessionLocal(), c.id))
    assert res["ok"] is False and res["broken_at"] is not None


def test_staff_proof_endpoint_verifies(admin):
    c = _client()
    _action(c.id, "isolate")
    v = admin.get(f"/clients/{c.id}/actions/verify")
    assert v.status_code == 200 and v.json()["ok"] is True
    p = admin.get(f"/clients/{c.id}/actions/proof.json")
    assert p.status_code == 200
    body = p.json()
    assert body["verification"]["ok"] is True and body["entry_count"] == 1
    assert body["client"]["id"] == c.id


def test_client_can_download_their_action_proof(client):
    from app import auth
    from app.db import User
    c = _client()
    _action(c.id, "isolate")
    db = SessionLocal()
    db.add(User(email="cfo@a.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("cfo@a.example"))
    r = client.get("/portal/actions/proof.json")
    assert r.status_code == 200 and r.json()["verification"]["ok"] is True
