"""The deployment-rendered module directory and the roster push to modules."""
import json

import httpx

from app import directory
from app.config import settings
from app.db import Module, SessionLocal

DIR = {
    "incident-response": {"base_url": "http://incident-response:8000/", "token": "irtok",
                          "public_url": "https://ir.example.com"},
    "managed-services": {"base_url": "http://managed-services:8000", "token": "mstok", "public_url": ""},
    "not-a-module": {"base_url": "http://x:1", "token": "t"},
}


def test_env_directory_fills_blank_rows_only(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "module_directory", json.dumps(DIR))
    db = SessionLocal()
    ms = db.get(Module, "managed-services")
    ms.base_url, ms.api_token = "http://operator-set:8200", "optok"
    db.commit()
    applied = directory.apply_env_directory(SessionLocal())
    assert applied == 1  # only incident-response was blank; the unknown key is ignored
    db = SessionLocal()
    ir = db.get(Module, "incident-response")
    assert ir.base_url == "http://incident-response:8000" and ir.api_token == "irtok"
    assert ir.public_url == "https://ir.example.com"
    assert db.get(Module, "managed-services").base_url == "http://operator-set:8200"
    # force overwrites the operator's edit with the deployment's values
    directory.apply_env_directory(SessionLocal(), force=True)
    assert SessionLocal().get(Module, "managed-services").api_token == "mstok"


def test_apply_directory_from_connections_page(admin, monkeypatch):
    monkeypatch.setattr(settings, "module_directory", json.dumps(DIR))
    r = admin.post("/connections/apply-directory", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert SessionLocal().get(Module, "incident-response").base_url == "http://incident-response:8000"


def test_push_sync_hits_each_connected_module(fresh_db):
    db = SessionLocal()
    for key, url, tok in [("incident-response", "http://incident-response:8000", "irtok"),
                          ("vulnerability-management", "http://vulnerability-management:8000", "vtok")]:
        m = db.get(Module, key)
        m.base_url, m.api_token = url, tok
    db.commit()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.method, req.url.path, req.headers.get("authorization")))
        if req.url.host == "vulnerability-management":
            return httpx.Response(502, json={"ok": False, "detail": "platform unreachable"})
        return httpx.Response(200, json={"ok": True, "roster": 3, "added": 1, "updated": 2, "deactivated": 0})

    res = directory.push_sync(SessionLocal(), wait=True, transport=httpx.MockTransport(handler))
    assert {h for h, *_ in seen} == {"incident-response", "vulnerability-management"}
    assert all(m == "POST" and p == "/api/provision/sync" for _, m, p, _ in seen)
    assert ("incident-response", "POST", "/api/provision/sync", "Bearer irtok") in seen
    assert res["incident-response"]["ok"] and "added 1" in res["incident-response"]["detail"]
    assert res["vulnerability-management"]["ok"] is False
    assert directory.LAST_PUSH["vulnerability-management"]["ok"] is False
    # scoping to one key only pushes that module
    seen.clear()
    directory.push_sync(SessionLocal(), keys={"incident-response"}, wait=True, transport=httpx.MockTransport(handler))
    assert [h for h, *_ in seen] == ["incident-response"]


def test_client_page_links_into_module(admin):
    admin.post("/connections/module/incident-response",
               data={"base_url": "http://incident-response:8000", "api_token": "t", "status": "in-progress",
                     "public_url": "https://ir.example.com"})
    admin.post("/clients", data={"name": "Riverbend Credit Union"})
    db = SessionLocal()
    from app.db import Client
    cid = db.query(Client).filter_by(name="Riverbend Credit Union").one().id
    admin.post(f"/clients/{cid}/modules/incident-response", data={"enabled": "true"})
    body = admin.get(f"/clients/{cid}").text
    assert f"https://ir.example.com/clients/platform/{cid}" in body
