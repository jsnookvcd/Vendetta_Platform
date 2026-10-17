"""Staff onboarding and access levels: profiles, per-module grants, the roster the
modules pull, the push to modules, and the SSO gate that admits only rostered
people once anyone is onboarded."""
import httpx

from app import auth, directory, oidc, staff
from app.config import settings
from app.db import Module, SessionLocal, Staff, User


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def _onboard(admin, email="dan@vendettacd.io", name="Dan Baker", profile="incident-responder"):
    r = admin.post("/staff", data={"email": email, "name": name, "title": "Director of IR", "profile": profile},
                   follow_redirects=False)
    assert r.status_code == 302, r.text
    return SessionLocal().query(Staff).filter_by(email=email).one()


def test_onboard_applies_profile_and_feeds_module_rosters(admin):
    p = _onboard(admin)
    assert p.platform_role == "analyst" and p.profile == "incident-responder"
    g = {x.module_key: x for x in p.grants}
    assert g["incident-response"].role == "analyst" and g["penetration-testing"].role == "analyst"
    assert g["managed-services"].config == {"can_act": True, "can_approve": True}
    ms = admin.get("/api/platform/staff", params={"module": "managed-services"}, headers=_bearer()).json()
    assert ms["governs"] is True
    assert ms["staff"] == [{"email": "dan@vendettacd.io", "name": "Dan Baker", "title": "Director of IR",
                            "role": "analyst", "config": {"can_act": True, "can_approve": True}}]
    # a module the profile grants "none" does not see them
    _onboard(admin, "red@vendettacd.io", "Red Teamer", "offensive-security")
    ir = admin.get("/api/platform/staff", params={"module": "incident-response"}, headers=_bearer()).json()
    assert [s["email"] for s in ir["staff"]] == ["dan@vendettacd.io"]
    pt = admin.get("/api/platform/staff", params={"module": "penetration-testing"}, headers=_bearer()).json()
    assert {s["email"] for s in pt["staff"]} == {"dan@vendettacd.io", "red@vendettacd.io"}
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anon:
        assert anon.get("/api/platform/staff", params={"module": "x"}).status_code == 401  # bearer required


def test_grant_edit_profile_and_deactivate(admin):
    p = _onboard(admin, profile="soc-analyst")
    # SOC analyst cannot approve; promote in managed services only
    r = admin.post(f"/staff/{p.id}/grant/managed-services",
                   data={"role": "admin", "can_act": "true", "can_approve": "true"}, follow_redirects=False)
    assert r.status_code == 302
    p = SessionLocal().get(Staff, p.id)
    g = {x.module_key: x for x in p.grants}
    assert g["managed-services"].role == "admin" and g["managed-services"].config["can_approve"] is True
    assert p.profile == "custom"
    assert g["penetration-testing"].role == "none"
    # administrator profile rewrites everything
    admin.post(f"/staff/{p.id}/profile", data={"profile": "administrator"}, follow_redirects=False)
    p = SessionLocal().get(Staff, p.id)
    assert p.platform_role == "admin" and all(x.role == "admin" for x in p.grants)
    # deactivation drops them from every module roster and from the platform login table
    db = SessionLocal()
    db.add(User(email=p.email, role="admin", active=True)); db.commit()
    admin.post(f"/staff/{p.id}/active", data={"active": "false"}, follow_redirects=False)
    assert SessionLocal().get(Staff, p.id).active is False
    assert SessionLocal().query(User).filter_by(email=p.email).one().active is False
    assert admin.get("/api/platform/staff", params={"module": "incident-response"}, headers=_bearer()).json()["staff"] == []
    everyone = admin.get("/api/platform/staff", headers=_bearer()).json()["staff"]
    assert everyone[0]["active"] is False and everyone[0]["modules"]["incident-response"]["role"] == "admin"


def test_staff_changes_push_to_modules(admin, monkeypatch):
    db = SessionLocal()
    for key in ("incident-response", "managed-services"):
        m = db.get(Module, key); m.base_url, m.api_token = f"http://{key}:8000", "t"
    db.commit()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.host)
        return httpx.Response(200, json={"ok": True})
    real = directory.push_sync
    monkeypatch.setattr(directory, "push_sync",
                        lambda db, keys=None, wait=False, transport=None: real(db, keys, True, httpx.MockTransport(handler)))
    _onboard(admin, profile="incident-responder")
    assert set(seen) == {"incident-response", "managed-services"}


def test_staff_pages_admin_only_for_changes(client, admin):
    p = _onboard(admin)
    assert admin.get("/staff").status_code == 200
    assert admin.get(f"/staff/{p.id}").status_code == 200
    # an analyst by SSO can look but not change
    db = SessionLocal()
    db.add(User(email="kenedi@vendettacd.io", role="analyst")); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("kenedi@vendettacd.io"))
    assert client.get("/staff").status_code == 200
    assert client.post("/staff", data={"email": "x@vendettacd.io", "profile": "leadership"}).status_code == 403
    assert client.post(f"/staff/{p.id}/active", data={"active": "false"}).status_code == 403


def test_sso_gate_uses_roster_once_anyone_is_onboarded(admin, monkeypatch):
    monkeypatch.setattr(settings, "internal_email_domains", "vendettacd.io")
    monkeypatch.setattr(settings, "admin_emails", "jordan@vendettacd.io")
    # empty roster: domain rule, as before
    assert oidc._map_identity({"email": "anyone@vendettacd.io"}) == ("anyone@vendettacd.io", "analyst", None)
    p = _onboard(admin, "dan@vendettacd.io", profile="administrator")
    # roster governs: rostered person gets their platform role, unrostered denied
    assert oidc._map_identity({"email": "dan@vendettacd.io"}) == ("dan@vendettacd.io", "admin", None)
    assert oidc._map_identity({"email": "anyone@vendettacd.io"}) is None
    # the configured admin email is always the bootstrap path
    assert oidc._map_identity({"email": "jordan@vendettacd.io"}) == ("jordan@vendettacd.io", "admin", None)
    # deactivated: denied
    admin.post(f"/staff/{p.id}/active", data={"active": "false"}, follow_redirects=False)
    assert oidc._map_identity({"email": "dan@vendettacd.io"}) is None


def test_cannot_deactivate_yourself(admin):
    db = SessionLocal()
    me = Staff(email="admin", name="break glass"); db.add(me); db.flush()
    staff.apply_profile(db, me, "administrator"); db.commit()
    r = admin.post(f"/staff/{me.id}/active", data={"active": "false"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().get(Staff, me.id).active is True


def test_office_of_special_projects_grants(admin):
    """OSP is grantable: the vCISO / advisory profile opens it (and SABINE) only;
    Administrator reaches it, Leadership reads it; the SOC and offensive profiles do not."""
    assert "professional-services" in staff.GRANTABLE
    v = _onboard(admin, "vciso@vendettacd.io", "Virtual CISO", "vciso-advisory")
    g = {x.module_key: x for x in v.grants}
    assert g["professional-services"].role == "analyst" and g["sabine"].role == "analyst"
    assert g["incident-response"].role == "none" and g["penetration-testing"].role == "none"
    lead = _onboard(admin, "lead@vendettacd.io", "Leader", "leadership")
    assert {x.module_key: x for x in lead.grants}["professional-services"].role == "viewer"
    boss = _onboard(admin, "boss@vendettacd.io", "Boss", "administrator")
    assert {x.module_key: x for x in boss.grants}["professional-services"].role == "admin"
    _onboard(admin, "soc@vendettacd.io", "SOC", "soc-analyst")
    _onboard(admin, "red@vendettacd.io", "Red", "offensive-security")
    osp = admin.get("/api/platform/staff", params={"module": "professional-services"}, headers=_bearer()).json()
    assert {s["email"]: s["role"] for s in osp["staff"]} == {
        "vciso@vendettacd.io": "analyst", "lead@vendettacd.io": "viewer", "boss@vendettacd.io": "admin"}


def test_mdr_grants_by_profile(admin):
    """MDR is grantable: Administrator admin, Incident responder and SOC analyst
    analyst, Leadership viewer, everyone else none; the roster MDR pulls follows."""
    assert "mdr" in staff.GRANTABLE
    expected = {"administrator": "admin", "incident-responder": "analyst", "soc-analyst": "analyst",
                "leadership": "viewer", "offensive-security": "none", "vciso-advisory": "none"}
    for profile, role in expected.items():
        p = _onboard(admin, f"{profile}@vendettacd.io", profile.title(), profile)
        assert {g.module_key: g.role for g in p.grants}["mdr"] == role, profile
    roster = admin.get("/api/platform/staff", params={"module": "mdr"}, headers=_bearer()).json()["staff"]
    assert {s["email"]: s["role"] for s in roster} == {
        "administrator@vendettacd.io": "admin", "incident-responder@vendettacd.io": "analyst",
        "soc-analyst@vendettacd.io": "analyst", "leadership@vendettacd.io": "viewer"}
    # a single grant can be set like any other module
    p = SessionLocal().query(Staff).filter_by(email="vciso-advisory@vendettacd.io").one()
    admin.post(f"/staff/{p.id}/grant/mdr", data={"role": "viewer"})
    p = SessionLocal().get(Staff, p.id)
    assert {g.module_key: g.role for g in p.grants}["mdr"] == "viewer"


def test_staff_change_reaches_the_slack_bridge(admin, monkeypatch):
    """The Slack responder has no grant of its own; it acts on incident-response and
    sabine grants, so a change to either must reach it so it drops its cached roster."""
    db = SessionLocal()
    for key in ("incident-response", "slack"):
        m = db.get(Module, key); m.base_url, m.api_token = f"http://{key}:8000", "t"
    db.commit()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.host)
        return httpx.Response(200, json={"ok": True})
    real = directory.push_sync
    monkeypatch.setattr(directory, "push_sync",
                        lambda db, keys=None, wait=False, transport=None: real(db, keys, True, httpx.MockTransport(handler)))
    _onboard(admin, profile="incident-responder")
    assert {"incident-response", "slack"} <= set(seen)
