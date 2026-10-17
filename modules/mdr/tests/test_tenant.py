"""Tenant isolation: a client sees only their own published investigations, cannot
probe or export another tenant's, cannot reach a staff route or the service API,
and the executive view is summary only."""
import datetime as dt
import types

import pytest

from app import auth
from app.db import Client, Investigation, SessionLocal, User
from helpers import as_user, finding, ingest, make_client


def _two(now):
    a = make_client(name="Client A", pid="pa", domains="a.example")
    b = make_client(name="Client B", pid="pb", domains="b.example")
    ingest([finding(fid="a1", pid="pa", client="Client A", host="A-WS01", at=now),
            finding(fid="a2", pid="pa", client="Client A", host="A-WS02", at=now),
            finding(fid="b1", pid="pb", client="Client B", host="B-WS01", at=now)], now=now)
    db = SessionLocal()
    invs = {i.host: i for i in db.query(Investigation).all()}
    for host in ("A-WS01", "B-WS01"):
        invs[host].published = True
        invs[host].client_summary = f"Summary for {host}"
    db.commit()
    return a, b, invs


def test_portal_lists_only_own_published(client, now):
    a, b, invs = _two(now)
    as_user(client, "it@a.example", "client", a.id)
    page = client.get("/portal").text
    assert "A-WS01" in page and "B-WS01" not in page and "A-WS02" not in page  # unpublished hidden


def test_detail_respects_tenant_and_publish(client, now):
    a, b, invs = _two(now)
    as_user(client, "it@a.example", "client", a.id)
    assert client.get(f"/portal/investigations/{invs['A-WS01'].id}").status_code == 200
    assert client.get(f"/portal/investigations/{invs['A-WS02'].id}").status_code == 404
    assert client.get(f"/portal/investigations/{invs['B-WS01'].id}").status_code == 404
    assert client.get("/portal/investigations/does-not-exist").status_code == 404


def test_export_respects_tenant_and_seals_internal(client, now, tmp_path):
    from app.evidence_export import verify_package
    a, b, invs = _two(now)
    staff_note_inv = invs["A-WS01"]
    db = SessionLocal()
    from app.db import record
    record(db, db.get(Investigation, staff_note_inv.id), "note", "analyst", "internal hypothesis")
    db.commit()
    as_user(client, "it@a.example", "client", a.id)
    assert client.get(f"/portal/investigations/{invs['B-WS01'].id}/evidence/export.zip").status_code == 404
    r = client.get(f"/portal/investigations/{staff_note_inv.id}/evidence/export.zip")
    assert r.status_code == 200
    assert b"internal hypothesis" not in r.content
    p = tmp_path / "c.zip"
    p.write_bytes(r.content)
    report = verify_package(str(p))
    assert report["ok"] is True


def test_client_cannot_act_or_reach_staff_or_api(client, now):
    a, b, invs = _two(now)
    as_user(client, "it@a.example", "client", a.id)
    for path in ("/", "/investigations", f"/investigations/{invs['B-WS01'].id}", "/rules", "/clients", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403), path
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"
    r = client.post(f"/investigations/{invs['A-WS01'].id}/ack", follow_redirects=False)
    assert r.status_code in (302, 403)
    assert SessionLocal().get(Investigation, invs["A-WS01"].id).acknowledged_at is None
    for path in ("/api/module", "/api/findings", "/api/metrics", "/api/suppressions"):
        assert client.get(path, follow_redirects=False).status_code in (302, 401, 403), path


def test_auth_backstop_refuses_client_session(client, now):
    a, _, _ = _two(now)
    db = SessionLocal()
    db.add(User(email="cfo@a.example", role="client", client_id=a.id))
    db.commit()
    req = types.SimpleNamespace(cookies={auth.COOKIE: auth.make_session("cfo@a.example")}, headers={}, method="GET")
    for fn in (auth.current_user, auth.api_user, auth.require_admin):
        with pytest.raises(Exception) as e:
            fn(req)
        assert getattr(e.value, "status_code", None) == 403
    good = types.SimpleNamespace(cookies={}, headers={"authorization": f"Bearer {auth.api_token()}"})
    assert auth.api_user(good) == "api"


def test_executive_view_is_summary_only(client, now):
    a, b, invs = _two(now)
    db = SessionLocal()
    db.get(Client, a.id).executive_emails = "ceo@a.example"
    db.commit()
    as_user(client, "ceo@a.example", "client", a.id)
    page = client.get("/portal").text
    assert "Executive view" in page and "Time to detect" in page
    assert "A-WS01" not in page  # no per-investigation table
    r = client.get(f"/portal/investigations/{invs['A-WS01'].id}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/portal"
    assert client.get(f"/portal/investigations/{invs['A-WS01'].id}/evidence/export.zip").status_code == 404


def test_portal_shows_client_metrics(client, now):
    a, b, invs = _two(now)
    db = SessionLocal()
    i = db.get(Investigation, invs["A-WS01"].id)
    i.acknowledged_at = now + dt.timedelta(minutes=4)
    db.commit()
    as_user(client, "it@a.example", "client", a.id)
    page = client.get("/portal").text
    assert "4m" in page  # A's own MTTA


def test_oidc_refuses_ambiguous_domain(client):
    from app import oidc
    a = make_client(name="Client A", pid="pa", domains="shared.example")
    b = make_client(name="Client B", pid="pb", domains="shared.example")
    assert oidc._map_identity({"email": "user@shared.example"}) is None
    db = SessionLocal()
    db.get(Client, b.id).portal_domains = "bravo.example"
    db.commit()
    mapped = oidc._map_identity({"email": "cfo@shared.example"})
    assert mapped is not None and mapped[1] == "client" and mapped[2] == a.id


@pytest.mark.parametrize("change", [{"active": False}, {"portal_enabled": False}])
def test_portal_closes_for_deactivated_or_portal_off_client(client, now, change):
    """An existing client session stops working on every portal route, the evidence
    export included, once the client is deactivated or its portal is switched off."""
    a, b, invs = _two(now)
    as_user(client, "it@a.example", "client", a.id)
    iid = invs["A-WS01"].id
    paths = ["/portal", f"/portal/investigations/{iid}", f"/portal/investigations/{iid}/evidence/export.zip"]
    assert all(client.get(p).status_code == 200 for p in paths)
    db = SessionLocal()
    c = db.get(Client, a.id)
    for k, v in change.items():
        setattr(c, k, v)
    db.commit()
    db.close()
    for p in paths:
        assert client.get(p, follow_redirects=False).status_code == 404, p
