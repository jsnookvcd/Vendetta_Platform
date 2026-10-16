"""Platform link shared by every client module: the control plane can push a
roster sync, deep-link into a client, and the module fails closed on placeholder
secrets. The roster is served by a mock control plane."""
import httpx
import pytest

from app import auth, boot, provision
from app.config import settings
from app.db import Client, SessionLocal

MODULE = "dark-web-monitoring"
ROSTER = {"clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "industry": "credit union",
     "portal_domains": "riverbendcu.org", "modules": [MODULE], "tools": {}},
]}


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def _platform(roster=ROSTER, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=roster)
    return httpx.MockTransport(handler)


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")


def _route(monkeypatch, transport):
    """Point the module's outbound httpx.Client at the mock control plane."""
    real = httpx.Client
    monkeypatch.setattr(provision.httpx, "Client",
                        lambda *a, **k: real(*a, **{**k, "transport": k.get("transport") or transport}))


def test_sync_endpoint_pulls_roster(client, monkeypatch):
    _configure(monkeypatch)
    _route(monkeypatch, _platform())
    r = client.post("/api/provision/sync", headers=_bearer())
    assert r.status_code == 200, r.text
    assert r.json()["ok"] and r.json()["added"] == 1
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").count() == 1
    st = provision.state()
    assert st["configured"] and st["token_set"] and st["last_ok"] is True


def test_sync_endpoint_reports_failure_and_requires_token(client, monkeypatch):
    _configure(monkeypatch)
    _route(monkeypatch, _platform(status=500))
    r = client.post("/api/provision/sync", headers=_bearer())
    assert r.status_code == 502 and r.json()["ok"] is False
    assert provision.state()["last_ok"] is False
    assert client.post("/api/provision/sync").status_code == 401


def test_sync_endpoint_409_when_unconfigured(client, monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "")
    assert client.post("/api/provision/sync", headers=_bearer()).status_code == 409


def test_deep_link_by_platform_id(admin):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", platform_client_id="plat-rb")
    db.add(c); db.commit()
    r = admin.get("/clients/platform/plat-rb", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == f"/clients/{c.id}"
    assert admin.get("/clients/platform/nope", follow_redirects=False).status_code == 404


def test_pull_keeps_local_portal_toggle(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_platform())
    db = SessionLocal()
    c = db.query(Client).filter_by(platform_client_id="plat-rb").one()
    assert c.portal_enabled is True  # new client inherits the platform state
    c.portal_enabled = False  # an operator turns the portal off in this module
    db.commit()
    provision.pull(SessionLocal(), transport=_platform())
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one().portal_enabled is False
    # losing every domain on the platform closes the portal here
    no_domains = {"clients": [dict(ROSTER["clients"][0], portal_domains="")]}
    provision.pull(SessionLocal(), transport=_platform(no_domains))
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one().portal_enabled is False


def test_boot_refuses_placeholder_secret(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "change-me")
    monkeypatch.setattr(settings, "allow_insecure_defaults", False)
    with pytest.raises(RuntimeError):
        boot.check()
    monkeypatch.setattr(settings, "allow_insecure_defaults", True)
    boot.check()  # allowed, with a warning
    monkeypatch.setattr(settings, "secret_key", "a-real-secret-value")
    monkeypatch.setattr(settings, "allow_insecure_defaults", False)
    assert boot.problems() == []


def test_api_token_setting_overrides_derived(monkeypatch):
    derived = auth.api_token()
    monkeypatch.setattr(settings, "api_token", "deployment-token")
    assert auth.api_token() == "deployment-token" != derived
