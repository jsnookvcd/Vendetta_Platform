"""Cross-module contracts: what this module serves at /api/findings and sends to the
hub must match docs/contracts/*.schema.json, the shapes every other module relies
on. The hub is mocked; the payload it receives is validated against the schema."""
import json
import os

import httpx
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from app import auth
from app.config import settings
from app.db import SessionLocal

CONTRACTS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "contracts")


def _schema(name):
    docs = {n: json.load(open(os.path.join(CONTRACTS, n))) for n in
            ("finding.schema.json", "escalation.schema.json", "escalation-result.schema.json")}
    registry = Registry().with_resources(
        (n, Resource.from_contents(d)) for n, d in docs.items()
    ).with_resources((d["$id"], Resource.from_contents(d)) for d in docs.values())
    return Draft202012Validator(docs[name], registry=registry)


def _check(name, instance):
    errors = sorted(_schema(name).iter_errors(instance), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def _hub(captured, case="VCD-IR-2026-801"):
    def handler(req: httpx.Request) -> httpx.Response:
        captured["path"] = req.url.path
        captured["auth"] = req.headers.get("authorization")
        captured["payload"] = json.loads(req.content)
        return httpx.Response(200, json={"case_id": case, "id": "hubid", "linked": False})
    return httpx.MockTransport(handler)


def _route_hub(monkeypatch, module, transport):
    real_client, real_post = httpx.Client, httpx.post
    monkeypatch.setattr(module.httpx, "Client",
                        lambda *a, **k: real_client(*a, **{**k, "transport": k.get("transport") or transport}))
    monkeypatch.setattr(module.httpx, "post",
                        lambda url, **k: real_client(transport=transport, headers=k.pop("headers", None),
                                                     timeout=k.pop("timeout", None)).post(url, **k))
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    monkeypatch.setattr(settings, "platform_hub_token", "hubtok")


from app import hub as platform_mod
from test_app import _synced_alert


def test_findings_match_shared_schema_and_filters(admin):
    fake, c, a = _synced_alert(admin)
    rows = admin.get("/api/findings", headers=_bearer()).json()
    assert rows
    for row in rows:
        _check("finding.schema.json", row)
    pid = SessionLocal().get(type(c), c.id).platform_client_id
    assert admin.get("/api/findings", params={"status": "open"}, headers=_bearer()).json()
    assert admin.get("/api/findings", params={"platform_client_id": "nope"}, headers=_bearer()).json() == []
    if pid:
        assert admin.get("/api/findings", params={"platform_client_id": pid}, headers=_bearer()).json()


def test_api_escalate_sends_shared_payload(admin, monkeypatch):
    fake, c, a = _synced_alert(admin)
    captured = {}
    _route_hub(monkeypatch, platform_mod, _hub(captured))
    r = admin.post(f"/api/findings/{a.id}/escalate", headers=_bearer())
    assert r.status_code == 200, r.text
    assert r.json()["escalated"] and r.json()["case"] == "VCD-IR-2026-801"
    assert captured["path"] == "/api/ir-cases" and captured["auth"] == "Bearer hubtok"
    _check("escalation.schema.json", captured["payload"])
