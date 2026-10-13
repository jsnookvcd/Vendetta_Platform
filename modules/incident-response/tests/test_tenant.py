"""Tenant isolation for the IR hub: a client user sees only their own cases, cannot
probe another client's case id, and cannot reach a staff route or the API."""
import types

import pytest

from app import auth
from app.db import Case, Client, SessionLocal, User, open_case


def _two_clients():
    db = SessionLocal()
    a, b = Client(name="Client A"), Client(name="Client B")
    db.add_all([a, b]); db.commit()
    return a, b


def _as_client(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_portal_lists_only_own_cases(client):
    a, b = _two_clients()
    db = SessionLocal()
    open_case(db, a, "A incident on file server")
    open_case(db, b, "B confidential breach")
    _as_client(client, "cfo@a.example", a)
    page = client.get("/portal").text
    assert "A incident on file server" in page and "B confidential breach" not in page


def test_portal_case_404s_for_other_tenant(client):
    a, b = _two_clients()
    db = SessionLocal()
    a_case = open_case(db, a, "mine")
    b_case = open_case(db, b, "not mine")
    _as_client(client, "it@a.example", a)
    assert client.get(f"/portal/cases/{a_case.id}").status_code == 200
    assert client.get(f"/portal/cases/{b_case.id}").status_code == 404
    assert client.get("/portal/cases/nope").status_code == 404


def test_client_session_cannot_reach_staff_routes(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    for path in ("/", "/cases", "/clients", "/declare", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403)
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"


def test_client_session_cannot_reach_api(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    assert client.get("/api/ir-cases", follow_redirects=False).status_code in (302, 401, 403)


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
    from app.db import Client
    a, b = _two_clients()
    aid, bid = a.id, b.id
    db = SessionLocal()
    ca, cb = db.get(Client, aid), db.get(Client, bid)
    ca.portal_enabled = cb.portal_enabled = True
    ca.portal_domains = cb.portal_domains = "shared.example"
    db.commit()
    assert oidc._map_identity({"email": "user@shared.example"}) is None  # ambiguous: refused
    db = SessionLocal()
    db.get(Client, bid).portal_domains = "bravo.example"
    db.commit()
    mapped = oidc._map_identity({"email": "cfo@shared.example"})
    assert mapped is not None and mapped[1] == "client" and mapped[2] == aid
