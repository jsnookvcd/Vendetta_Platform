"""Pulling the client roster and tool mappings from the platform control plane."""
import httpx
import pytest

from app import provision
from app.config import settings
from app.db import Client, SessionLocal

ROSTER = {"module": "managed-services", "clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "slug": "riverbend-credit-union",
     "industry": "credit union", "portal_domains": "riverbendcu.org",
     "modules": ["managed-services"],
     "tools": {"sentinelone": "111,112", "crowdstrike": "aabbccdd", "acronis": "ten-rb"}},
    {"id": "plat-hp", "name": "Harbor Point Logistics", "slug": "harbor-point",
     "industry": "transport", "portal_domains": "", "modules": ["managed-services"],
     "tools": {"crowdstrike": "ddeeff00"}},
]}


def _transport(roster=ROSTER, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/platform/clients"
        assert req.url.params["module"] == "managed-services"
        assert req.headers["authorization"] == "Bearer ptok"
        return httpx.Response(status, json=roster)
    return httpx.MockTransport(handler)


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")


def test_pull_upserts_clients_and_tool_mappings(fresh_db, monkeypatch):
    _configure(monkeypatch)
    db = SessionLocal()
    summ = provision.pull(db, transport=_transport())
    assert summ == {"roster": 2, "added": 2, "updated": 0, "deactivated": 0}
    db = SessionLocal()
    rb = db.query(Client).filter_by(platform_client_id="plat-rb").one()
    assert rb.name == "Riverbend Credit Union" and rb.portal_enabled is True
    assert rb.portal_domains == "riverbendcu.org"
    assert rb.sentinelone_site_ids == "111,112" and rb.crowdstrike_cid == "aabbccdd"
    assert rb.acronis_tenant_id == "ten-rb" and rb.huntress_org_id == ""
    assert rb.tools == ["sentinelone", "crowdstrike", "acronis"]


def test_pull_is_idempotent_and_updates_mappings(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_transport())
    changed = {"clients": [dict(ROSTER["clients"][0], tools={"sentinelone": "999"}),
                           ROSTER["clients"][1]]}
    summ = provision.pull(SessionLocal(), transport=_transport(changed))
    assert summ["added"] == 0 and summ["updated"] == 2
    rb = SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one()
    assert rb.sentinelone_site_ids == "999" and rb.crowdstrike_cid == ""  # dropped from mapping


def test_pull_adopts_hand_created_client_by_name(fresh_db, monkeypatch):
    _configure(monkeypatch)
    db = SessionLocal()
    db.add(Client(name="Riverbend Credit Union"))
    db.commit()
    provision.pull(SessionLocal(), transport=_transport())
    db = SessionLocal()
    assert db.query(Client).filter(Client.name == "Riverbend Credit Union").count() == 1
    assert db.query(Client).filter_by(platform_client_id="plat-rb").one().name == "Riverbend Credit Union"


def test_pull_deactivates_dropped_clients(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_transport())
    smaller = {"clients": [ROSTER["clients"][0]]}  # Harbor Point gone
    summ = provision.pull(SessionLocal(), transport=_transport(smaller))
    assert summ["deactivated"] == 1
    hp = SessionLocal().query(Client).filter_by(platform_client_id="plat-hp").one()
    assert hp.active is False  # kept, not deleted


def test_pull_errors_are_typed(fresh_db, monkeypatch):
    _configure(monkeypatch)
    with pytest.raises(provision.ProvisionError, match="token"):
        provision.pull(SessionLocal(), transport=_transport(status=403))

    def boom(req):
        raise httpx.ConnectError("refused")
    with pytest.raises(provision.ProvisionError, match="unreachable"):
        provision.pull(SessionLocal(), transport=httpx.MockTransport(boom))


def test_pull_route_requires_platform_configured(admin):
    r = admin.post("/clients/pull", follow_redirects=False)
    assert "err=" in r.headers["location"]  # no PLATFORM_URL in test env
