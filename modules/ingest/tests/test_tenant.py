"""Tenant boundaries and role gates: a client sees only its own chain and proofs,
viewers cannot change anything, only admins handle credentials, and stored
secrets never come back out."""
import json

from sqlalchemy import select

from app import pipeline
from app.db import Connector, Event, SessionLocal
from helpers import as_user, bearer, make_client, make_connector, signin


def _two_tenants():
    a = make_client()
    b = make_client(name="Beta Bank", pid="plat-beta", domains="beta.example")
    ca, cb = make_connector(a), make_connector(b)
    db = SessionLocal()
    pipeline.ingest_records(db, db.get(Connector, ca.id), [signin(1)])
    pipeline.ingest_records(db, db.get(Connector, cb.id), [signin(1, user="carol@beta.example")])
    pipeline.seal(db)
    evs = {e.tenant: e.id for e in db.execute(select(Event)).scalars()}
    db.close()
    return a, b, evs


def test_portal_client_gets_own_proof_and_chain_only(client):
    a, b, evs = _two_tenants()
    as_user(client, "it@acme.example", role="client", client_id=a.id)
    mine = client.get(f"/portal/events/{evs['plat-acme']}/proof")
    assert mine.status_code == 200 and json.loads(mine.content)["receipt"]["tenant"] == "plat-acme"
    assert client.get(f"/portal/events/{evs['plat-beta']}/proof").status_code == 404
    chain = json.loads(client.get("/portal/chain.json").content)
    assert chain["tenant"] == "plat-acme" and all(x["header"]["tenant"] == "plat-acme" for x in chain["batches"])
    assert client.get("/portal").status_code == 200


def test_portal_session_cannot_reach_staff_pages_or_the_api(client):
    a, _, evs = _two_tenants()
    as_user(client, "it@acme.example", role="client", client_id=a.id)
    for path in ("/", "/events", f"/events/{evs['plat-acme']}/proof", "/receipts", "/connectors"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/portal", path
    r = client.get("/api/findings", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/portal"


def test_portal_closed_when_disabled(client):
    a = make_client(portal=False)
    as_user(client, "it@acme.example", role="client", client_id=a.id)
    assert client.get("/portal").status_code == 404


def test_viewer_reads_but_cannot_change(client):
    _two_tenants()
    as_user(client, "v@vendettacd.io", role="viewer")
    assert client.get("/events").status_code == 200
    assert client.get("/receipts").status_code == 200
    assert client.post("/seal").status_code == 403
    assert client.post("/stream/run").status_code == 403


def test_only_admins_add_connectors_and_secrets_never_render(client):
    a = make_client()
    as_user(client, "an@vendettacd.io", role="analyst")
    form = {"client_id": a.id, "source": "entra_signins", "config.tenant_id": "contoso.onmicrosoft.com",
            "config.client_id": "app-1", "cred.client_secret": "SUPER-SECRET-VALUE"}
    assert client.post("/connectors", data=form).status_code == 403
    as_user(client, "ad@vendettacd.io", role="admin")
    r = client.post("/connectors", data=form, follow_redirects=False)
    assert r.status_code == 302
    page = client.get(r.headers["location"]).text
    assert "SUPER-SECRET-VALUE" not in page
    assert "Push secret (shown once)" in page
    again = client.get(r.headers["location"]).text
    assert "Push secret (shown once)" not in again
    conn = SessionLocal().execute(select(Connector)).scalar_one()
    from sqlalchemy import text
    raw = SessionLocal().execute(text("select credentials from connectors")).scalar_one()
    assert "SUPER-SECRET-VALUE" not in raw and raw.startswith("enc:v1:")
    assert json.loads(conn.credentials)["client_secret"] == "SUPER-SECRET-VALUE"
    for path in ("/connectors", "/api/connectors", "/api/catalog"):
        body = client.get(path, headers=bearer() if path.startswith("/api") else {}).text
        assert "SUPER-SECRET-VALUE" not in body


def test_connector_needs_an_active_platform_client(admin):
    c = make_client(pid="")
    r = admin.post("/connectors", data={"client_id": c.id, "source": "entra_signins"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_events_api_requires_a_tenant(client):
    _two_tenants()
    assert client.get("/api/events", headers=bearer()).status_code == 422
    rows = client.get("/api/events?platform_client_id=plat-beta", headers=bearer()).json()
    assert rows and all(r["event"]["metadata"]["tenant_uid"] == "plat-beta" for r in rows)


def test_api_requires_the_token(client):
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/findings", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_staff_pages_render(admin):
    _, _, evs = _two_tenants()
    for path in ("/", "/events", f"/events/{evs['plat-acme']}", "/detections", "/connectors", "/rules",
                 "/rules/new", "/receipts", "/clients", "/settings"):
        assert admin.get(path).status_code == 200, path
    rid = admin.get("/api/module", headers=bearer()).status_code
    assert rid == 200
