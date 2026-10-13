"""Tenant isolation, proven rather than assumed. Two clients A and B; a signed-in
A user must never read, probe or act on B's data, and a client session must never
reach a staff route or the service API, with or without the middleware gate."""
import types

import pytest

from app import auth
from app.db import (ActionLog, Alert, Channel, Client, Device, Message, SessionLocal,
                    User, get_channel)


def _two_clients():
    db = SessionLocal()
    a = Client(name="Client A", portal_enabled=True, portal_domains="a.example")
    b = Client(name="Client B", portal_enabled=True, portal_domains="b.example")
    db.add_all([a, b]); db.commit()
    return a, b


def _device(c, host):
    db = SessionLocal()
    d = Device(client_id=c.id, tool="sentinelone", external_id=f"dev-{c.id}", hostname=host, status="online")
    db.add(d); db.commit()
    return d


def _alert(c, title, published, dev=None, status="open"):
    db = SessionLocal()
    a = Alert(client_id=c.id, tool="sentinelone", external_id=f"al-{c.id}-{title}", kind="threat",
              severity="high", title=title, status=status, published=published,
              client_note=f"note for {title}", device_id=dev.id if dev else None)
    db.add(a); db.commit()
    return a


def _as_client(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


# ---------------------------------------------------------------- portal reads
def test_portal_lists_only_own_published_data(client):
    a, b = _two_clients()
    _alert(a, "A critical exposure", published=True)
    _alert(b, "B secret incident", published=True)
    _as_client(client, "cfo@a.example", a)
    page = client.get("/portal").text
    assert "A critical exposure" in page or "note for A critical exposure" in page
    assert "B secret incident" not in page and "note for B secret incident" not in page


def test_portal_detail_404s_for_other_tenant_and_unpublished(client):
    a, b = _two_clients()
    a_pub = _alert(a, "A shared", published=True)
    a_unpub = _alert(a, "A internal", published=False)
    b_pub = _alert(b, "B shared", published=True)
    _as_client(client, "it@a.example", a)
    assert client.get(f"/portal/alerts/{a_pub.id}").status_code == 200
    assert client.get(f"/portal/alerts/{a_unpub.id}").status_code == 404   # own but unpublished
    assert client.get(f"/portal/alerts/{b_pub.id}").status_code == 404     # other tenant
    assert client.get(f"/portal/alerts/does-not-exist").status_code == 404


def test_portal_messages_are_per_tenant(client):
    a, b = _two_clients()
    _as_client(client, "cfo@a.example", a)
    client.post("/portal/messages/soc", data={"body": "A private question"})
    db = SessionLocal()
    a_ch = db.query(Channel).filter_by(client_id=a.id, desk="soc").one()
    assert db.query(Channel).filter_by(client_id=b.id).count() == 0
    assert db.query(Message).filter_by(channel_id=a_ch.id).count() == 1


# ---------------------------------------------------------------- staff/API denial
def test_client_session_cannot_reach_staff_routes(client):
    a, _ = _two_clients()
    _as_client(client, "cfo@a.example", a)
    for path in ("/", "/clients", f"/clients/{a.id}", "/alerts", "/messages", "/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 403), f"{path} returned {r.status_code}"
        if r.status_code == 302:
            assert r.headers["location"] == "/portal"


def test_client_session_cannot_reach_service_api(client):
    a, _ = _two_clients()
    _alert(a, "A finding", published=False)
    _as_client(client, "cfo@a.example", a)
    # the gate redirects a client cookie away from /api; never a 200 with data
    r = client.get("/api/findings", follow_redirects=False)
    assert r.status_code in (302, 401, 403)


def test_auth_backstop_refuses_client_session_without_the_gate(client):
    """Prove the route-level half directly: even bypassing the middleware, a client
    session is refused by current_user and api_user."""
    a, _ = _two_clients()
    db = SessionLocal()
    db.add(User(email="cfo@a.example", role="client", client_id=a.id)); db.commit()
    req = types.SimpleNamespace(cookies={auth.COOKIE: auth.make_session("cfo@a.example")}, headers={})
    with pytest.raises(Exception) as e1:
        auth.current_user(req)
    assert getattr(e1.value, "status_code", None) == 403
    with pytest.raises(Exception) as e2:
        auth.api_user(req)
    assert getattr(e2.value, "status_code", None) == 403
    # the bearer still works for the API
    good = types.SimpleNamespace(cookies={}, headers={"authorization": f"Bearer {auth.api_token()}"})
    assert auth.api_user(good) == "api"


def test_admin_session_still_reaches_staff_routes(admin):
    a, _ = _two_clients()
    assert admin.get("/").status_code == 200
    assert admin.get(f"/clients/{a.id}").status_code == 200
    assert admin.get("/api/module", headers={"Authorization": f"Bearer {auth.api_token()}"}).status_code == 200
