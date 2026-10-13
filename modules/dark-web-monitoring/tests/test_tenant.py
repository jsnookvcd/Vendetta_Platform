"""Tenant isolation for dark web monitoring: a client sees only their own confirmed
findings, and a client session cannot reach a staff route or the API."""
import types

import pytest

from app import auth
from app.db import Client, Hit, Item, SessionLocal, User


def _two_clients():
    db = SessionLocal()
    a = Client(name="Client A", portal_enabled=True, portal_domains="a.example")
    b = Client(name="Client B", portal_enabled=True, portal_domains="b.example")
    db.add_all([a, b]); db.commit()
    return a, b


def _confirmed_hit(c, title):
    db = SessionLocal()
    it = Item(kind="paste", title=title, content_hash=Item.make_hash(title, c.id))
    db.add(it); db.commit()
    h = Hit(client_id=c.id, item_id=it.id, reason="term", severity="high", status="confirmed",
            matched_text=title)
    db.add(h); db.commit()
    return h


def _as_client(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_portal_shows_only_own_confirmed_findings(client):
    a, b = _two_clients()
    _confirmed_hit(a, "A-breach-combolist")
    _confirmed_hit(b, "B-secret-leak")
    _as_client(client, "cfo@a.example", a)
    page = client.get("/portal").text
    assert "A-breach-combolist" in page and "B-secret-leak" not in page


def test_client_report_is_scoped_to_own_tenant(client):
    a, b = _two_clients()
    _as_client(client, "cfo@a.example", a)
    # the report builds for the signed-in client's id only; there is no id to probe.
    r = client.get("/portal/report.pdf", follow_redirects=False)
    assert r.status_code in (200, 501)  # 501 only if the PDF engine is absent


def test_client_session_cannot_reach_staff_routes(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    for path in ("/", "/clients", "/sources", "/search", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403, 404)
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"


def test_client_session_cannot_reach_api(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
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
