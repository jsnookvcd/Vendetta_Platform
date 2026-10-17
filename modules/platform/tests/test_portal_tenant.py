"""The client portal on the control plane and its tenant boundary: sign-in maps a
user to one client by portal domain (an ambiguous domain is refused), the portal
shows only the signed-in client's tier, services, accepted journey and approved
communications, detail routes 404 across tenants, and a client session reaches
nothing but /portal, refused in the gate and again at every route."""
import types

import pytest

from app import auth, oidc
from app.config import settings
from app.db import Client, Communication, JourneyItem, Module, SessionLocal
from helpers import make_client, sign_in_as


@pytest.fixture()
def two(admin):
    a = make_client(admin, "Alpha Bank", portal_domains="alpha.example", portal_enabled="true", tier="premier",
                    executive_emails="ceo@alpha.example")
    b = make_client(admin, "Bravo Credit Union", portal_domains="bravo.example", portal_enabled="true")
    return a, b


def _item(c, title, status):
    db = SessionLocal()
    i = JourneyItem(client_id=c.id, title=title, area="identity", status=status)
    db.add(i); db.commit()
    return i


def _comm(c, title, published=True, status="approved"):
    db = SessionLocal()
    m = Communication(client_id=c.id, kind="posture_review", title=title, subject=title, body_md=f"Body of {title}",
                      status=status, published=published)
    db.add(m); db.commit()
    return m


# ---------------------------------------------------------------- sign-in mapping
def test_sso_maps_client_by_domain(two, monkeypatch):
    a, b = two
    monkeypatch.setattr(settings, "internal_email_domains", "vendettacd.io")
    assert oidc._map_identity({"email": "cfo@alpha.example"}) == ("cfo@alpha.example", "client", a.id)
    assert oidc._map_identity({"email": "it@BRAVO.example"}) == ("it@bravo.example", "client", b.id)
    assert oidc._map_identity({"email": "x@nowhere.example"}) is None
    # internal staff are never mapped to a client
    assert oidc._map_identity({"email": "dan@vendettacd.io"})[1] == "analyst"


def test_sso_refuses_portal_off_inactive_and_ambiguous(two):
    a, b = two
    db = SessionLocal()
    db.get(Client, b.id).portal_enabled = False
    db.commit()
    assert oidc._map_identity({"email": "it@bravo.example"}) is None
    db = SessionLocal()
    db.get(Client, b.id).portal_enabled = True
    db.get(Client, b.id).active = False
    db.commit()
    assert oidc._map_identity({"email": "it@bravo.example"}) is None
    # two clients claiming one domain (the edit form refuses it; force it here) is refused, not guessed
    db = SessionLocal()
    db.get(Client, b.id).active = True
    db.get(Client, a.id).portal_domains = db.get(Client, b.id).portal_domains = "shared.example"
    db.commit()
    assert oidc._map_identity({"email": "user@shared.example"}) is None


def test_client_still_maps_once_the_staff_roster_governs(admin, two, monkeypatch):
    a, _ = two
    monkeypatch.setattr(settings, "internal_email_domains", "vendettacd.io")
    admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan", "profile": "administrator"})
    assert oidc._map_identity({"email": "cfo@alpha.example"}) == ("cfo@alpha.example", "client", a.id)
    assert oidc._map_identity({"email": "someone@vendettacd.io"}) is None


# ---------------------------------------------------------------- what the portal shows
def test_portal_home_shows_only_own_data(client, admin, two):
    a, b = two
    for st in ("proposed", "planned", "in_progress", "done", "declined"):
        _item(a, f"Alpha {st} item", st)
    _item(b, "Bravo planned item", "planned")
    _comm(a, "Alpha approved review")
    _comm(a, "Alpha draft review", published=False, status="draft")
    _comm(b, "Bravo approved review")
    sign_in_as(client, "it@alpha.example", "client", a.id)
    page = client.get("/portal").text
    assert "Alpha Bank" in page and "Premier" in page and "5" in page and "60" in page
    for st in ("planned", "in_progress", "done"):
        assert f"Alpha {st} item" in page
    assert "Alpha proposed item" not in page and "Alpha declined item" not in page
    assert "Alpha approved review" in page and "Alpha draft review" not in page
    assert "Bravo" not in page


def test_service_tiles_link_into_enabled_module_portals(client, admin, two):
    a, _ = two
    for key, url in (("managed-services", "https://ms.example.com"), ("sabine", "https://sabine.example.com"),
                     ("dark-web-monitoring", "https://dw.example.com"), ("mdr", "https://mdr.example.com")):
        admin.post(f"/connections/module/{key}", data={"base_url": f"http://{key}:8000", "status": "in-progress",
                                                       "public_url": url})
    for key in ("managed-services", "sabine", "mdr"):
        admin.post(f"/clients/{a.id}/modules/{key}", data={"enabled": "true"})
    sign_in_as(client, "it@alpha.example", "client", a.id)
    page = client.get("/portal").text
    assert 'href="https://ms.example.com/portal"' in page and 'href="https://mdr.example.com/portal"' in page
    assert "sabine.example.com" not in page  # SABINE has no client portal
    assert "dw.example.com" not in page  # not turned on for this client


def test_executive_view_is_labelled(client, two):
    a, _ = two
    sign_in_as(client, "ceo@alpha.example", "client", a.id)
    assert "executive view" in client.get("/portal").text
    sign_in_as(client, "it@alpha.example", "client", a.id)
    assert "executive view" not in client.get("/portal").text


def test_communication_detail_respects_tenant_and_publish(client, two):
    a, b = two
    mine = _comm(a, "Alpha approved review")
    draft = _comm(a, "Alpha draft", published=False, status="draft")
    theirs = _comm(b, "Bravo approved review")
    sign_in_as(client, "it@alpha.example", "client", a.id)
    r = client.get(f"/portal/communications/{mine.id}")
    assert r.status_code == 200 and "Body of Alpha approved review" in r.text
    assert client.get(f"/portal/communications/{draft.id}").status_code == 404
    assert client.get(f"/portal/communications/{theirs.id}").status_code == 404
    assert client.get("/portal/communications/does-not-exist").status_code == 404


def test_portal_closes_when_the_client_portal_is_switched_off(client, two):
    a, _ = two
    sign_in_as(client, "it@alpha.example", "client", a.id)
    assert client.get("/portal").status_code == 200
    db = SessionLocal()
    db.get(Client, a.id).portal_enabled = False
    db.commit()
    assert client.get("/portal").status_code == 404


# ---------------------------------------------------------------- the boundary
def test_client_session_is_gated_to_the_portal(client, two):
    a, b = two
    sign_in_as(client, "it@alpha.example", "client", a.id)
    for path in ("/", "/clients", f"/clients/{a.id}", f"/clients/{b.id}", "/communications", "/staff",
                 "/settings", "/connections", "/readiness"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/portal", path
    r = client.post(f"/clients/{a.id}/edit", data={"portal_domains": "evil.example"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/portal"
    for path in ("/api/module", "/api/platform/clients", f"/api/platform/clients/{a.id}/journey",
                 f"/api/platform/clients/{b.id}/communications", f"/api/platform/clients/{a.id}/360"):
        assert client.get(path, follow_redirects=False).status_code == 403, path
    r = client.post(f"/api/platform/clients/{b.id}/journey", json={"title": "x", "area": "data"})
    assert r.status_code == 403
    assert SessionLocal().get(Client, a.id).portal_domains == "alpha.example"
    assert client.get("/logout", follow_redirects=False).status_code == 302


def test_route_level_backstop_refuses_a_client_session(two):
    """Even with the gate bypassed, every staff route and the service API refuse a
    client at the route, and the portal refuses staff."""
    a, _ = two
    sign = auth.make_session("it@alpha.example")
    db = SessionLocal()
    from app.db import User
    db.add(User(email="it@alpha.example", role="client", client_id=a.id)); db.commit()
    req = types.SimpleNamespace(cookies={auth.COOKIE: sign}, headers={}, method="GET")
    for fn in (auth.current_user, auth.api_user, auth.require_internal):
        with pytest.raises(Exception) as e:
            fn(req)
        assert getattr(e.value, "status_code", None) == 403
    assert auth.require_client(req).client_id == a.id
    staff_req = types.SimpleNamespace(cookies={auth.COOKIE: auth.make_session("admin")}, headers={}, method="GET")
    with pytest.raises(Exception) as e:
        auth.require_client(staff_req)
    assert e.value.status_code == 403
    # require_owned: another tenant's record, or an unpublished one, is a 404
    ident = auth.resolve_identity(req)
    other = types.SimpleNamespace(client_id="someone-else")
    with pytest.raises(Exception) as e:
        auth.require_owned(ident, other)
    assert e.value.status_code == 404


def test_staff_and_anonymous_cannot_open_the_portal(client, admin, two):
    assert admin.get("/portal").status_code == 403
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anon:
        r = anon.get("/portal", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"].startswith("/login")


def test_a_client_session_for_a_deleted_client_sees_nothing(client, two):
    sign_in_as(client, "ghost@alpha.example", "client", "no-such-client")
    assert client.get("/portal").status_code == 404


def test_planned_module_never_appears_as_a_tile(client, admin, two):
    a, _ = two
    admin.post("/connections/module/network-operations",
               data={"base_url": "http://n:8000", "status": "planned", "public_url": "https://noc.example.com"})
    db = SessionLocal()
    db.get(Module, "network-operations").has_portal = True
    db.commit()
    admin.post(f"/clients/{a.id}/modules/network-operations", data={"enabled": "true"})
    sign_in_as(client, "it@alpha.example", "client", a.id)
    assert "noc.example.com" not in client.get("/portal").text
