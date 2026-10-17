"""Client 360: live reads from each module with its bearer token, filtered to the
client's platform id, cached briefly, and degrading gracefully when a module is
down, refusing the token or not connected."""
import httpx

from app import client360
from app.db import Module, SessionLocal
from helpers import bearer, make_client

WIRED = ("mdr", "managed-services", "dark-web-monitoring", "vulnerability-management", "incident-response",
         "professional-services")


def _wire(admin, c):
    db = SessionLocal()
    for key in WIRED:
        m = db.get(Module, key)
        m.base_url, m.api_token, m.status = f"http://{key}:8000", f"tok-{key}", "in-progress"
    db.commit()
    # vulnerability-management is connected but not turned on for this client;
    # penetration-testing is turned on but not connected
    for key in ("mdr", "managed-services", "dark-web-monitoring", "incident-response", "professional-services",
                "penetration-testing"):
        admin.post(f"/clients/{c.id}/modules/{key}", data={"enabled": "true"})


def _finding(pid, sev, title, **extra):
    return {"id": title, "title": title, "severity": sev, "status": "open",
            "subject": {"platform_client_id": pid, "client": "x"}, **extra}


def _handler(pid, calls):
    def handler(req: httpx.Request) -> httpx.Response:
        host = req.url.host
        calls.append((host, req.url.path, dict(req.url.params), req.headers.get("authorization")))
        if host == "dark-web-monitoring":
            raise httpx.ConnectError("refused")
        if host == "mdr":
            return httpx.Response(200, json=[
                _finding(pid, "critical", "Credential dumping on FS01", number="MDR-2026-0001",
                         native_status="new", verdict="pending", acknowledged_at=None),
                _finding(pid, "medium", "Suspicious PowerShell", number="MDR-2026-0002",
                         native_status="investigating", acknowledged_at="2026-10-17T10:00:00+00:00"),
                _finding("someone-else", "critical", "Other tenant investigation"),
            ])
        if host == "managed-services":
            return httpx.Response(200, json=[_finding(pid, "high", "EDR agent offline"),
                                             _finding(pid, "info", "Backup warning"),
                                             _finding("someone-else", "critical", "Not ours")])
        if host == "incident-response":
            return httpx.Response(200, json=[
                {"id": "c1", "number": "VCD-IR-2026-0007", "title": "BEC investigation", "severity": "high",
                 "status": "investigating", "client": {"platform_client_id": pid, "name": "x"}},
                {"id": "c2", "number": "VCD-IR-2026-0008", "title": "Other tenant case", "severity": "critical",
                 "status": "open", "client": {"platform_client_id": "someone-else"}},
            ])
        if host == "professional-services":
            return httpx.Response(200, json=[{
                "id": "e1", "name": "vCISO retainer", "status": "active", "overdue": False, "progress": 40,
                "subject": {"platform_client_id": pid},
                "deliverables": [{"id": "d1", "title": "IR plan", "status": "delivered"},
                                 {"id": "d2", "title": "Policy set", "status": "accepted"}]}])
        return httpx.Response(404)
    return handler


def test_360_reads_filters_and_degrades(admin):
    c = make_client(admin)
    _wire(admin, c)
    calls = []
    client360.use_transport(httpx.MockTransport(_handler(c.id, calls)))
    out = admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer()).json()

    by_host = {h: (p, q, a) for h, p, q, a in calls}
    assert by_host["mdr"] == ("/api/findings", {"status": "active", "platform_client_id": c.id}, "Bearer tok-mdr")
    assert by_host["incident-response"][:2] == ("/api/ir-cases", {"status": "active", "platform_client_id": c.id})
    assert by_host["professional-services"][:2] == ("/api/engagements",
                                                    {"status": "open", "platform_client_id": c.id})
    assert "vulnerability-management" not in by_host and "penetration-testing" not in by_host

    mods = {m["key"]: m for m in out["findings"]["modules"]}
    assert mods["mdr"]["state"] == "ok" and mods["mdr"]["total"] == 2
    assert mods["managed-services"]["by_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert mods["dark-web-monitoring"]["state"] == "unreachable" and "ConnectError" in mods["dark-web-monitoring"]["detail"]
    assert mods["vulnerability-management"]["state"] == "not_enabled"
    assert mods["penetration-testing"]["state"] == "not_connected"
    assert out["findings"]["total"] == 4
    assert out["findings"]["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}

    assert out["mdr"]["open"] == 2 and out["mdr"]["unacknowledged"] == 1
    assert out["mdr"]["items"][0]["number"] == "MDR-2026-0001"
    assert [x["number"] for x in out["incident_response"]["cases"]] == ["VCD-IR-2026-0007"]
    osp = out["professional_services"]
    assert osp["open"] == 1 and osp["deliverables_waiting"] == 1
    assert osp["engagements"][0]["waiting"][0]["title"] == "IR plan"
    assert "Other tenant" not in str(out) and "Not ours" not in str(out)
    assert out["client"]["commitments"] == {"critical_ack_minutes": 15, "critical_contain_minutes": 240}


def test_360_includes_journey_and_drafts(admin):
    c = make_client(admin)
    admin.post(f"/api/platform/clients/{c.id}/journey", json={"title": "MFA", "area": "identity",
                                                              "source_ref": "r1"}, headers=bearer())
    admin.post(f"/api/platform/clients/{c.id}/communications",
               json={"kind": "outreach", "title": "Hello", "source_ref": "o1"}, headers=bearer())
    out = admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer()).json()
    assert out["journey"]["counts"]["proposed"] == 1 and out["journey"]["items"][0]["title"] == "MFA"
    assert out["communications"]["drafts"] == 1 and out["communications"]["items"][0]["title"] == "Hello"
    assert all(m["state"] == "not_enabled" for m in out["findings"]["modules"])
    assert admin.get("/api/platform/clients/nope/360", headers=bearer()).status_code == 404


def test_360_is_cached_and_refreshable(admin):
    c = make_client(admin)
    _wire(admin, c)
    calls = []
    client360.use_transport(httpx.MockTransport(_handler(c.id, calls)))
    admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer())
    n = len(calls)
    admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer())
    assert len(calls) == n  # served from the cache
    admin.get(f"/api/platform/clients/{c.id}/360", params={"refresh": "true"}, headers=bearer())
    assert len(calls) == 2 * n
    admin.post(f"/clients/{c.id}/refresh-360")
    admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer())
    assert len(calls) == 3 * n


def test_rejected_token_and_http_errors_show_unreachable(admin):
    c = make_client(admin)
    _wire(admin, c)

    def handler(req):
        return httpx.Response(401 if req.url.host == "mdr" else 500)
    client360.use_transport(httpx.MockTransport(handler))
    out = admin.get(f"/api/platform/clients/{c.id}/360", headers=bearer()).json()
    assert out["mdr"]["state"] == "unreachable" and out["mdr"]["detail"] == "module rejected the token"
    assert out["incident_response"]["detail"] == "http 500"


def test_client_page_renders_the_360_panel(admin):
    c = make_client(admin)
    _wire(admin, c)
    client360.use_transport(httpx.MockTransport(_handler(c.id, [])))
    page = admin.get(f"/clients/{c.id}").text
    assert "Client 360" in page and "MDR investigations" in page
    assert "MDR-2026-0001" in page and "VCD-IR-2026-0007" in page and "vCISO retainer" in page
    assert "unreachable: unreachable: ConnectError" not in page and "unreachable" in page
    assert "1 deliverable waiting on the client" in page
