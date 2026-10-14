"""Tenant isolation: a client sees only their own published engagements/deliverables,
cannot probe or accept another tenant's deliverable, and cannot reach a staff route
or the service API."""
import types

import pytest

from app import auth
from app.db import Client, Deliverable, Engagement, SessionLocal, User


def _two_clients():
    db = SessionLocal()
    a = Client(name="Client A", portal_enabled=True, portal_domains="a.example", platform_client_id="pa")
    b = Client(name="Client B", portal_enabled=True, portal_domains="b.example", platform_client_id="pb")
    db.add_all([a, b]); db.commit()
    return a, b


def _eng(c, name, published=True, status="active"):
    db = SessionLocal()
    e = Engagement(client_id=c.id, name=name, kind="vciso", status=status, published=published)
    db.add(e); db.commit()
    return e


def _deliv(e, c, title, status="delivered"):
    db = SessionLocal()
    d = Deliverable(engagement_id=e.id, client_id=c.id, title=title, kind="policy", status=status)
    db.add(d); db.commit()
    return d


def _as_client(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_portal_lists_only_own_published(client):
    a, b = _two_clients()
    _deliv(_eng(a, "A engagement"), a, "A deliverable")
    _deliv(_eng(b, "B engagement"), b, "B deliverable")
    _as_client(client, "cfo@a.example", a)
    page = client.get("/portal").text
    assert "A engagement" in page and "B engagement" not in page


def test_engagement_detail_respects_tenant_and_publish(client):
    a, b = _two_clients()
    a_pub = _eng(a, "A pub", published=True)
    a_unpub = _eng(a, "A unpub", published=False)
    b_pub = _eng(b, "B pub", published=True)
    _as_client(client, "it@a.example", a)
    assert client.get(f"/portal/engagements/{a_pub.id}").status_code == 200
    assert client.get(f"/portal/engagements/{a_unpub.id}").status_code == 404
    assert client.get(f"/portal/engagements/{b_pub.id}").status_code == 404


def test_cannot_accept_other_tenant_deliverable(client):
    a, b = _two_clients()
    bd = _deliv(_eng(b, "B", published=True), b, "B deliverable", status="delivered")
    _as_client(client, "cfo@a.example", a)
    assert client.post(f"/portal/deliverables/{bd.id}/accept", follow_redirects=False).status_code == 404
    assert SessionLocal().get(Deliverable, bd.id).status == "delivered"


def test_client_cannot_reach_staff_or_api(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    for path in ("/", "/clients", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403)
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"
    assert client.get("/api/module", follow_redirects=False).status_code in (302, 401, 403)


def test_auth_backstop_refuses_client_session(client):
    a, _ = _two_clients()
    db = SessionLocal()
    db.add(User(email="cfo@a.example", role="client", client_id=a.id)); db.commit()
    req = types.SimpleNamespace(cookies={auth.COOKIE: auth.make_session("cfo@a.example")}, headers={})
    for fn in (auth.current_user, auth.api_user):
        with pytest.raises(Exception) as e:
            fn(req)
        assert getattr(e.value, "status_code", None) == 403
    good = types.SimpleNamespace(cookies={}, headers={"authorization": f"Bearer {auth.api_token()}"})
    assert auth.api_user(good) == "api"


def test_oidc_refuses_ambiguous_domain(client):
    from app import oidc
    a, b = _two_clients()
    aid, bid = a.id, b.id
    db = SessionLocal()
    db.get(Client, aid).portal_domains = db.get(Client, bid).portal_domains = "shared.example"
    db.commit()
    assert oidc._map_identity({"email": "user@shared.example"}) is None
    db = SessionLocal()
    db.get(Client, bid).portal_domains = "bravo.example"
    db.commit()
    mapped = oidc._map_identity({"email": "cfo@shared.example"})
    assert mapped is not None and mapped[2] == aid
