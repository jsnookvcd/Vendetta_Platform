"""The hub pulls the shared finding model from each module, maps findings to its own
clients by platform_client_id then name, and degrades gracefully when a module is
down."""
import httpx

from app import findings as fm
from app.db import Client, SessionLocal


def _sources():
    return [{"name": "dark-web-monitoring", "base_url": "https://dw.local", "token": "t1"},
            {"name": "managed-services", "base_url": "https://msp.local", "token": "t2"}]


def _finding(fid, module, pid, client_name, sev="high"):
    return {"id": fid, "module": module, "severity": sev, "type": "detection",
            "status": "new", "title": f"{module} {fid}", "created_at": "2026-10-13T12:00:00+00:00",
            "subject": {"platform_client_id": pid, "client": client_name}}


def _transport(dw_findings, msp_findings, dw_status=200, msp_status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/findings"
        if req.url.host == "dw.local":
            return httpx.Response(dw_status, json=dw_findings)
        return httpx.Response(msp_status, json=msp_findings)
    return httpx.MockTransport(handler)


def setup_function():
    fm.clear_cache()


def test_pull_all_aggregates_and_tags_source(client):
    t = _transport([_finding("h1", "dark-web-monitoring", "plat-a", "Alpha")],
                   [_finding("a1", "managed-services", "plat-a", "Alpha")])
    out = fm.pull_all(_sources(), transport=t, force=True)
    assert {s["name"]: s["reachable"] for s in out["sources"]} == {
        "dark-web-monitoring": True, "managed-services": True}
    assert {f["_source"] for f in out["findings"]} == {"dark-web-monitoring", "managed-services"}


def test_for_client_matches_by_platform_id(client):
    db = SessionLocal()
    c = Client(name="Alpha"); c.platform_client_id = "plat-a"
    db.add(c); db.commit()
    t = _transport([_finding("h1", "dark-web-monitoring", "plat-a", "Alpha"),
                    _finding("h2", "dark-web-monitoring", "plat-b", "Bravo")],
                   [_finding("a1", "managed-services", "plat-a", "Alpha")])
    db = SessionLocal(); c = db.query(Client).filter_by(name="Alpha").one()
    out = fm.for_client(c, _sources(), transport=t, force=True)
    ids = {f["id"] for f in out["findings"]}
    assert ids == {"h1", "a1"}  # plat-b finding excluded


def test_for_client_falls_back_to_name(client):
    db = SessionLocal()
    c = Client(name="Cedar Valley"); c.platform_client_id = ""
    db.add(c); db.commit()
    t = _transport([_finding("h9", "dark-web-monitoring", "", "Cedar Valley")], [])
    db = SessionLocal(); c = db.query(Client).filter_by(name="Cedar Valley").one()
    out = fm.for_client(c, _sources(), transport=t, force=True)
    assert {f["id"] for f in out["findings"]} == {"h9"}


def test_unreachable_module_degrades_gracefully(client):
    t = _transport([_finding("h1", "dark-web-monitoring", "plat-a", "Alpha")], [], msp_status=503)
    out = fm.pull_all(_sources(), transport=t, force=True)
    byname = {s["name"]: s for s in out["sources"]}
    assert byname["dark-web-monitoring"]["reachable"] is True
    assert byname["managed-services"]["reachable"] is False
    assert [f["id"] for f in out["findings"]] == ["h1"]  # the reachable module still contributes


def test_findings_page_renders(admin):
    r = admin.get("/findings")
    assert r.status_code == 200 and "Findings" in r.text


# ---------------------------------------------------------------- platform discovery
def test_discovers_sources_from_platform_when_unset(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")
    monkeypatch.setattr(settings, "findings_sources", "")  # force discovery

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/platform/modules":
            assert req.headers["authorization"] == "Bearer ptok"
            return httpx.Response(200, json={"modules": [
                {"name": "vulnerability-management", "base_url": "https://vuln.local", "token": "vtok",
                 "findings_path": "/api/findings"},
                {"name": "penetration-testing", "base_url": "https://pentest.local", "token": "ptok2",
                 "findings_path": "/api/findings"}]})
        if req.url.path == "/api/findings":
            if req.url.host == "vuln.local":
                return httpx.Response(200, json=[_finding("v1", "vulnerability-management", "plat-a", "Alpha")])
            return httpx.Response(200, json=[_finding("p1", "penetration-testing", "plat-a", "Alpha")])
        raise AssertionError(req.url)

    out = fm.pull_all(transport=httpx.MockTransport(handler), force=True)
    names = {s["name"] for s in out["sources"]}
    assert names == {"vulnerability-management", "penetration-testing"}
    assert {f["id"] for f in out["findings"]} == {"v1", "p1"}
