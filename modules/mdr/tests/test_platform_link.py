"""Platform link shared by every client module: the control plane can push a
roster sync, deep-link into a client, and the module fails closed on placeholder
secrets. The roster is served by a mock control plane."""
import httpx
import pytest

from app import auth, boot, provision
from app.config import settings
from app.db import Client, SessionLocal
from helpers import bearer

MODULE = "mdr"
ROSTER = {"clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "industry": "credit union",
     "portal_domains": "riverbendcu.org", "executive_emails": "ceo@riverbendcu.org", "modules": [MODULE],
     "tools": {}},
]}


def _platform(roster=ROSTER, status=200, seen=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append((req.url.path, dict(req.url.params)))
        if req.url.path == "/api/platform/staff":
            return httpx.Response(200, json={"governs": False, "staff": []})
        return httpx.Response(status, json=roster)
    return httpx.MockTransport(handler)


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")


def _route(monkeypatch, transport):
    real = httpx.Client
    monkeypatch.setattr(provision.httpx, "Client",
                        lambda *a, **k: real(*a, **{**k, "transport": k.get("transport") or transport}))


def test_sync_endpoint_pulls_roster_for_mdr(client, monkeypatch):
    _configure(monkeypatch)
    seen = []
    _route(monkeypatch, _platform(seen=seen))
    r = client.post("/api/provision/sync", headers=bearer())
    assert r.status_code == 200, r.text
    assert r.json()["ok"] and r.json()["added"] == 1
    assert ("/api/platform/clients", {"module": "mdr"}) in seen
    assert ("/api/platform/staff", {"module": "mdr"}) in seen
    c = SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one()
    assert c.executive_emails == "ceo@riverbendcu.org" and c.portal_enabled
    st = provision.state()
    assert st["configured"] and st["token_set"] and st["last_ok"] is True


def test_sync_endpoint_reports_failure_and_requires_token(client, monkeypatch):
    _configure(monkeypatch)
    _route(monkeypatch, _platform(status=500))
    r = client.post("/api/provision/sync", headers=bearer())
    assert r.status_code == 502 and r.json()["ok"] is False
    assert provision.state()["last_ok"] is False
    assert client.post("/api/provision/sync").status_code == 401


def test_sync_endpoint_409_when_unconfigured(client, monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "")
    assert client.post("/api/provision/sync", headers=bearer()).status_code == 409


def test_dropped_client_is_deactivated_and_signals_stop_mapping(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_platform())
    provision.pull(SessionLocal(), transport=_platform({"clients": []}))
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one().active is False
    from app import detect
    from helpers import finding
    db = SessionLocal()
    summ = detect.upsert_signals(db, [finding(pid="plat-rb", client="Riverbend Credit Union")])
    db.commit()
    assert summ["unmapped"] == 1


def test_deep_link_by_platform_id(admin):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", platform_client_id="plat-rb")
    db.add(c)
    db.commit()
    r = admin.get("/clients/platform/plat-rb", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == f"/clients/{c.id}"
    assert admin.get("/clients/platform/nope", follow_redirects=False).status_code == 404


def test_deep_link_requires_staff(client):
    r = client.get("/clients/platform/plat-rb", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login")


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


def test_startup_fails_closed_on_placeholder(fresh_db, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr(settings, "secret_key", "replace-with-64-random-chars")
    monkeypatch.setattr(settings, "allow_insecure_defaults", False)
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_api_token_setting_overrides_derived(monkeypatch):
    derived = auth.api_token()
    monkeypatch.setattr(settings, "api_token", "deployment-token")
    assert auth.api_token() == "deployment-token" != derived


def test_readiness_reports_signal_source(client, monkeypatch):
    monkeypatch.setattr(settings, "managed_services_url", "http://managed-services:8000")
    monkeypatch.setattr(settings, "evidence_signing_key", "")
    body = client.get("/api/module", headers=bearer()).json()["readiness"]
    ms = body["integrations"]["managed_services"]
    assert ms["configured"] is True and ms["token_set"] is False and ms["interval_seconds"] == 0
    assert body["keys"]["signing_applicable"] is True and body["keys"]["signing_dedicated"] is False
