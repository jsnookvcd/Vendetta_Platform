"""IR hub pulling its roster from the platform, and escalation resolving a client
by the shared platform id."""
import httpx
import pytest

from app import auth, hub, provision
from app.config import settings
from app.db import Case, Client, SessionLocal

from test_hub import DW_PAYLOAD, _bearer

ROSTER = {"module": "incident-response", "clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "industry": "credit union",
     "portal_domains": "riverbendcu.org", "modules": ["incident-response"]},
    {"id": "plat-hp", "name": "Harbor Point Logistics", "industry": "transport",
     "portal_domains": "", "modules": ["incident-response", "managed-services"]},
]}


def _transport(roster=ROSTER, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/platform/clients"
        assert req.url.params["module"] == "incident-response"
        return httpx.Response(status, json=roster)
    return httpx.MockTransport(handler)


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")


def test_pull_upserts_roster(fresh_db, monkeypatch):
    _configure(monkeypatch)
    summ = provision.pull(SessionLocal(), transport=_transport())
    assert {k: summ[k] for k in ("roster", "added", "updated", "deactivated")} == {"roster": 2, "added": 2, "updated": 0, "deactivated": 0}
    rb = SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one()
    assert rb.industry == "credit union" and rb.portal_enabled and rb.portal_domains == "riverbendcu.org"


def test_pull_leaves_ir_owned_data_alone(fresh_db, monkeypatch):
    _configure(monkeypatch)
    db = SessionLocal()
    from app.db import Retainer, open_case
    c = Client(name="Riverbend Credit Union"); db.add(c); db.commit()
    db.add(Retainer(client_id=c.id, active=True, tier="Core", named_responders="A. Reyes")); db.commit()
    case = open_case(db, c, "existing matter")
    provision.pull(SessionLocal(), transport=_transport())
    db = SessionLocal()
    c2 = db.query(Client).filter_by(platform_client_id="plat-rb").one()
    assert c2.id == c.id and c2.retainer is not None  # adopted by name, retainer kept
    assert db.query(Case).filter_by(client_id=c.id).count() == 1


def test_pull_deactivates_dropped(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_transport())
    summ = provision.pull(SessionLocal(), transport=_transport({"clients": [ROSTER["clients"][0]]}))
    assert summ["deactivated"] == 1
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-hp").one().active is False


def test_escalation_resolves_by_platform_id(client):
    # the hub already knows this client under a different local id, bound to plat-rb
    db = SessionLocal()
    c = Client(name="Riverbend CU (hub name differs)", platform_client_id="plat-rb")
    db.add(c); db.commit()
    payload = dict(DW_PAYLOAD, platform_client_id="plat-rb")
    r = client.post("/api/ir-cases", json=payload, headers=_bearer())
    assert r.status_code == 200
    db = SessionLocal()
    case = db.query(Case).filter_by(number=r.json()["case_id"]).one()
    assert case.client_id == c.id  # matched the existing client by platform id, not by name
    assert db.query(Client).count() == 1  # no duplicate created


def test_escalation_stamps_platform_id_on_name_match(client):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union")  # no platform id yet
    db.add(c); db.commit()
    client.post("/api/ir-cases", json=dict(DW_PAYLOAD, platform_client_id="plat-rb"), headers=_bearer())
    db = SessionLocal()
    assert db.query(Client).filter_by(name="Riverbend Credit Union").one().platform_client_id == "plat-rb"


def test_pull_errors_typed(fresh_db, monkeypatch):
    _configure(monkeypatch)
    with pytest.raises(provision.ProvisionError, match="token"):
        provision.pull(SessionLocal(), transport=_transport(status=403))


def test_clients_page_shows_pull_banner_when_platform_configured(admin, monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    page = admin.get("/clients").text
    assert "Pull from platform" in page


def test_clients_page_without_platform(admin, monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "")
    page = admin.get("/clients").text
    assert "Add client" in page and "Pull from platform" not in page
