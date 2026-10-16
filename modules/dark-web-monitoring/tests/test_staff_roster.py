"""The staff roster from the control plane: mirrored into this module's users
table, consulted live at SSO sign-in, and honored offline from the mirror."""
import httpx

from app import oidc, provision
from app.config import settings
from app.db import SessionLocal, User

MODULE = "dark-web-monitoring"
ROSTER = {"module": MODULE, "governs": True, "staff": [
    {"email": "dan@vendettacd.io", "name": "Dan Baker", "title": "Director of IR", "role": "admin",
     "config": {"can_act": True, "can_approve": True}},
    {"email": "sam@vendettacd.io", "name": "Sam", "title": "", "role": "analyst",
     "config": {"can_act": True, "can_approve": False}},
]}


def _platform(body=ROSTER, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/platform/staff":
            assert req.url.params["module"] == MODULE
            return httpx.Response(status, json=body)
        return httpx.Response(200, json={"clients": []})
    return httpx.MockTransport(handler)


def _configure(monkeypatch, transport):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")
    monkeypatch.setattr(settings, "internal_email_domains", "vendettacd.io")
    monkeypatch.setattr(settings, "admin_emails", "")
    real = httpx.Client
    monkeypatch.setattr(provision.httpx, "Client",
                        lambda *a, **k: real(*a, **{**k, "transport": k.get("transport") or transport}))
    provision._STAFF_CACHE.update(at=0.0, body=None)


def test_pull_mirrors_roster_and_deactivates_removed(fresh_db, monkeypatch):
    _configure(monkeypatch, _platform())
    summ = provision.pull(SessionLocal())
    assert summ["staff"] == 2 and summ["staff_added"] == 2
    db = SessionLocal()
    dan = db.query(User).filter_by(email="dan@vendettacd.io").one()
    assert dan.role == "admin" and dan.source == "platform" and dan.active
    if hasattr(dan, "can_approve"):
        sam = db.query(User).filter_by(email="sam@vendettacd.io").one()
        assert dan.can_approve is True and sam.can_approve is False and sam.can_act is True
    # Sam is dropped from the roster: deactivated here, row kept
    _configure(monkeypatch, _platform({"governs": True, "staff": ROSTER["staff"][:1]}))
    summ = provision.pull(SessionLocal())
    assert summ["staff_deactivated"] == 1
    assert SessionLocal().query(User).filter_by(email="sam@vendettacd.io").one().active is False
    st = provision.state()["staff"]
    assert st["governs"] is True and st["count"] == 1 and st["last_ok"] is True


def test_sso_admits_rostered_denies_unrostered(fresh_db, monkeypatch):
    _configure(monkeypatch, _platform())
    assert oidc._map_identity({"email": "dan@vendettacd.io"}) == ("dan@vendettacd.io", "admin", None)
    assert oidc._map_identity({"email": "sam@vendettacd.io"}) == ("sam@vendettacd.io", "analyst", None)
    # internal domain but not rostered for this module: denied
    assert oidc._map_identity({"email": "someone@vendettacd.io"}) is None
    # the live lookup mirrored them locally
    assert SessionLocal().query(User).filter_by(email="dan@vendettacd.io").one().source == "platform"


def test_sso_falls_back_to_domain_rules_without_roster(fresh_db, monkeypatch):
    _configure(monkeypatch, _platform({"governs": False, "staff": []}))
    monkeypatch.setattr(settings, "admin_emails", "jordan@vendettacd.io")
    assert oidc._map_identity({"email": "someone@vendettacd.io"}) == ("someone@vendettacd.io", "analyst", None)
    assert oidc._map_identity({"email": "jordan@vendettacd.io"}) == ("jordan@vendettacd.io", "admin", None)
    # no control plane at all: same
    monkeypatch.setattr(settings, "platform_url", "")
    assert oidc._map_identity({"email": "someone@vendettacd.io"}) == ("someone@vendettacd.io", "analyst", None)


def test_sso_uses_mirror_when_control_plane_is_down(fresh_db, monkeypatch):
    _configure(monkeypatch, _platform())
    provision.pull(SessionLocal())  # mirror populated
    _configure(monkeypatch, _platform(status=503))
    assert oidc._map_identity({"email": "dan@vendettacd.io"}) == ("dan@vendettacd.io", "admin", None)
    assert oidc._map_identity({"email": "someone@vendettacd.io"}) is None
