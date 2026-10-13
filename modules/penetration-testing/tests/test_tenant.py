"""Tenant isolation: a client sees only their own shared engagements/findings, cannot
probe another tenant's finding or report, and cannot reach a staff route or the API."""
import types

import pytest

from app import auth
from app.db import Client, Engagement, Finding, RemediationStep, SessionLocal, User


def _two_clients():
    db = SessionLocal()
    a = Client(name="Client A", portal_enabled=True, portal_domains="a.example", platform_client_id="pa")
    b = Client(name="Client B", portal_enabled=True, portal_domains="b.example", platform_client_id="pb")
    db.add_all([a, b]); db.commit()
    return a, b


def _eng(c, name, published=True):
    db = SessionLocal()
    e = Engagement(client_id=c.id, name=name, kind="external", status="reporting", published=published)
    db.add(e); db.commit()
    return e


def _finding(e, c, title):
    db = SessionLocal()
    f = Finding(engagement_id=e.id, client_id=c.id, title=title, asset="h", cvss=7.0, severity="high", status="open")
    db.add(f); db.commit()
    return f


def _as_client(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_portal_lists_only_own_shared(client):
    a, b = _two_clients()
    _finding(_eng(a, "A test"), a, "A finding")
    _finding(_eng(b, "B test"), b, "B finding")
    _as_client(client, "cfo@a.example", a)
    page = client.get("/portal").text
    assert "A finding" in page and "B finding" not in page


def test_finding_detail_respects_tenant_and_publish(client):
    a, b = _two_clients()
    a_pub = _finding(_eng(a, "A pub", published=True), a, "A shared")
    a_unpub = _finding(_eng(a, "A unpub", published=False), a, "A internal")
    b_pub = _finding(_eng(b, "B pub", published=True), b, "B shared")
    _as_client(client, "it@a.example", a)
    assert client.get(f"/portal/findings/{a_pub.id}").status_code == 200
    assert client.get(f"/portal/findings/{a_unpub.id}").status_code == 404
    assert client.get(f"/portal/findings/{b_pub.id}").status_code == 404


def test_cannot_toggle_other_tenant_step(client):
    a, b = _two_clients()
    bf = _finding(_eng(b, "B", published=True), b, "B finding")
    db = SessionLocal()
    s = RemediationStep(finding_id=bf.id, position=0, text="x"); db.add(s); db.commit()
    _as_client(client, "cfo@a.example", a)
    assert client.post(f"/portal/findings/{bf.id}/steps/{s.id}", follow_redirects=False).status_code == 404


def test_client_cannot_reach_staff_or_api(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    for path in ("/", "/clients", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403)
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"
    assert client.get("/api/findings", follow_redirects=False).status_code in (302, 401, 403)


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
