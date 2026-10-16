"""Control-plane behaviour: registry seeding, client directory, per-client module
and tool activation, the provisioning API contract, the overview probe (graceful),
and the module switch."""
import httpx

from app import aggregate, auth
from app.registry import DEFAULT_MODULES
from app.config import settings
from app.db import Client, ClientModule, ClientTool, Module, SessionLocal, ToolConnection


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_registry_seeds_modules_and_tools(fresh_db):
    db = SessionLocal()
    assert db.query(Module).count() == len(DEFAULT_MODULES)
    assert db.get(Module, "managed-services").status == "in-progress"
    assert {t.key for t in db.query(ToolConnection).all()} == {
        "superops", "sentinelone", "crowdstrike", "huntress", "acronis"}


def test_add_client_slugs_and_rejects_duplicates(admin):
    r = admin.post("/clients", data={"name": "Riverbend Credit Union", "industry": "credit union"},
                   follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/clients/")
    db = SessionLocal()
    c = db.query(Client).one()
    assert c.slug == "riverbend-credit-union"
    dup = admin.post("/clients", data={"name": "riverbend credit union"}, follow_redirects=False)
    assert "err=" in dup.headers["location"] and db.query(Client).count() == 1


def _client(admin, name="Riverbend Credit Union"):
    admin.post("/clients", data={"name": name})
    return SessionLocal().query(Client).filter_by(name=name).one()


def test_activate_module_and_tool_per_client(admin):
    c = _client(admin)
    admin.post(f"/clients/{c.id}/modules/managed-services", data={"enabled": "true"})
    admin.post(f"/clients/{c.id}/modules/dark-web-monitoring", data={"enabled": "true"})
    db = SessionLocal()
    cm = db.query(ClientModule).filter_by(client_id=c.id, module_key="managed-services").one()
    assert cm.enabled and cm.activated_by == "admin"
    cc = db.get(Client, c.id)
    assert cc.enabled_modules() == {"managed-services", "dark-web-monitoring"}
    # map tools
    admin.post(f"/clients/{c.id}/tool/sentinelone", data={"tenancy": "111, 112", "enabled": "true"})
    admin.post(f"/clients/{c.id}/tool/crowdstrike", data={"tenancy": "aabbccdd", "enabled": "true"})
    admin.post(f"/clients/{c.id}/tool/huntress", data={"tenancy": "", "enabled": "true"})  # blank: not enabled
    db = SessionLocal()
    cc = db.get(Client, c.id)
    assert cc.tool_map() == {"sentinelone": "111, 112", "crowdstrike": "aabbccdd"}
    # deactivate
    admin.post(f"/clients/{c.id}/modules/dark-web-monitoring", data={"enabled": "false"})
    assert SessionLocal().get(Client, c.id).enabled_modules() == {"managed-services"}


def test_provisioning_api_contract(admin):
    c = _client(admin)
    admin.post(f"/clients/{c.id}/edit", data={"industry": "credit union",
                                              "portal_domains": "riverbendcu.org",
                                              "executive_emails": "CEO@riverbendcu.org, cfo@riverbendcu.org",
                                              "active": "true"})
    admin.post(f"/clients/{c.id}/modules/managed-services", data={"enabled": "true"})
    admin.post(f"/clients/{c.id}/tool/sentinelone", data={"tenancy": "111,112", "enabled": "true"})
    # a second client without managed-services
    other = _client(admin, "Cedar Valley")
    admin.post(f"/clients/{other.id}/modules/dark-web-monitoring", data={"enabled": "true"})

    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as anon:
        assert anon.get("/api/platform/clients").status_code == 401
        ms = anon.get("/api/platform/clients", params={"module": "managed-services"}, headers=_bearer()).json()
        dw = anon.get("/api/platform/clients", params={"module": "dark-web-monitoring"}, headers=_bearer()).json()
    names = [x["name"] for x in ms["clients"]]
    assert names == ["Riverbend Credit Union"]  # only the one with managed-services on
    entry = ms["clients"][0]
    assert entry["id"] == c.id and entry["portal_domains"] == "riverbendcu.org"
    # executive emails are normalised (lower-cased, sorted) and carried in the roster
    assert entry["executive_emails"] == "ceo@riverbendcu.org,cfo@riverbendcu.org"
    assert entry["tools"] == {"sentinelone": "111,112"}
    assert [x["name"] for x in dw["clients"]] == ["Cedar Valley"]
    assert "tools" not in dw["clients"][0]  # tool map only for managed-services


def test_overview_probe_is_graceful_and_reads_counts(admin):
    db = SessionLocal()
    m = db.get(Module, "managed-services")
    m.base_url = "https://ms.example"
    m.api_token = "tok"
    db.commit()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/module":
            assert req.headers["authorization"] == "Bearer tok"
            return httpx.Response(200, json={"enabled": True, "tools": {"sentinelone": True, "acronis": False}})
        if req.url.path == "/api/findings":
            return httpx.Response(200, json=[{"severity": "critical"}, {"severity": "low"}, {"severity": "high"}])
        return httpx.Response(404)

    aggregate.clear_cache()
    res = aggregate.probe_module(m, transport=httpx.MockTransport(handler))
    assert res["reachable"] and res["enabled"] is True
    assert res["open"] == 3 and res["critical"] == 2 and res["tools"]["sentinelone"] is True

    # a dead module degrades, never raises
    def boom(req):
        raise httpx.ConnectError("refused")

    aggregate.clear_cache()
    dead = aggregate.probe_module(m, transport=httpx.MockTransport(boom))
    assert dead["reachable"] is False and "unreachable" in dead["detail"]


def test_refresh_tool_health_from_managed_services(admin):
    db = SessionLocal()
    m = db.get(Module, "managed-services")
    m.base_url = "https://ms.example"
    db.commit()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/module":
            return httpx.Response(200, json={"enabled": True, "tools": {
                "superops": True, "sentinelone": True, "crowdstrike": False,
                "huntress": True, "acronis": True}})
        return httpx.Response(200, json=[])

    # drive the probe through the mock, then the route reads the cached result
    aggregate.clear_cache()
    aggregate.probe_module(m, transport=httpx.MockTransport(handler))
    # refresh route re-probes (force), so seed the cache result it will read by
    # monkeypatching probe to the mock-backed call
    import app.main as main_mod
    orig = aggregate.probe_module
    aggregate.probe_module = lambda mod, force=False, transport=None: orig(mod, transport=httpx.MockTransport(handler), force=True)
    try:
        r = admin.post("/connections/refresh", follow_redirects=False)
    finally:
        aggregate.probe_module = orig
    assert "msg=" in r.headers["location"]
    db = SessionLocal()
    assert db.get(ToolConnection, "sentinelone").configured is True
    assert db.get(ToolConnection, "crowdstrike").configured is False


def test_connections_save_module_endpoint(admin):
    r = admin.post("/connections/module/incident-response",
                   data={"base_url": "https://ir.vendettacd.io/", "api_token": "irtok", "status": "in-progress"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
    m = SessionLocal().get(Module, "incident-response")
    assert m.base_url == "https://ir.vendettacd.io" and m.api_token == "irtok"


def test_module_on_off(client):
    settings.module_enabled = False
    try:
        assert client.get("/").status_code == 503
        assert client.get("/api/module", headers=_bearer()).json()["enabled"] is False
        assert client.get("/healthz").status_code == 200
    finally:
        settings.module_enabled = True
    assert client.get("/login").status_code == 200


def test_portal_domain_must_be_unique_across_clients(admin):
    a = _client(admin, "Alpha")
    b = _client(admin, "Bravo")
    admin.post(f"/clients/{a.id}/edit", data={"portal_domains": "shared.example", "active": "true"})
    # Bravo cannot take the same domain
    r = admin.post(f"/clients/{b.id}/edit", data={"portal_domains": "shared.example", "active": "true"},
                   follow_redirects=False)
    assert "err=" in r.headers["location"]
    db = SessionLocal()
    assert db.get(Client, b.id).portal_domains == ""  # not saved
    # a different domain is fine
    r = admin.post(f"/clients/{b.id}/edit", data={"portal_domains": "bravo.example", "active": "true"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
