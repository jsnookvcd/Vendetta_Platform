"""Hub side of the cross-module contracts: a schema-valid escalation from any module
opens or links a case, the reply matches the result schema, and the hub's own
findings pull sends the status vocabulary every module understands."""
import json
import os

import httpx
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from app import auth, findings as findings_mod
from app.db import Case, Client, SessionLocal

CONTRACTS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "contracts")


def _validator(name):
    docs = {n: json.load(open(os.path.join(CONTRACTS, n))) for n in
            ("finding.schema.json", "escalation.schema.json", "escalation-result.schema.json")}
    registry = Registry().with_resources((n, Resource.from_contents(d)) for n, d in docs.items())
    registry = registry.with_resources((d["$id"], Resource.from_contents(d)) for d in docs.values())
    return Draft202012Validator(docs[name], registry=registry)


def _check(name, instance):
    errors = list(_validator(name).iter_errors(instance))
    assert not errors, "\n".join(e.message for e in errors)


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def _finding(module, pid, name, title):
    return {"id": "f1", "module": module, "platform": "Vendetta Platform",
            "subject": {"client_id": "local-x", "platform_client_id": pid, "client": name, "case_ref": ""},
            "type": "vulnerability", "reason": "greenbone", "severity": "high", "status": "new",
            "title": title, "matched": "10.0.0.5", "source_group": "Greenbone", "url": "",
            "published_at": None, "created_at": None, "analyst_notes": "", "evidence": [],
            "workstream": "Resilience and Hardening"}


def _payload(module="vulnerability-management", pid="plat-rb", name="Riverbend Credit Union",
             title="[Vuln] OpenSSL < 3.0.14 on 10.0.0.5", **over):
    p = {"source_module": module, "client_id": "local-x", "platform_client_id": pid, "client": name,
         "case_ref": "", "severity": "high", "summary": title, "title": title,
         "workstream": "Resilience and Hardening", "finding": _finding(module, pid, name, title)}
    p.update(over)
    return p


def test_schema_valid_escalation_opens_case_and_links_on_case_ref(client):
    p = _payload()
    _check("escalation.schema.json", p)
    r = client.post("/api/ir-cases", json=p, headers=_bearer())
    assert r.status_code == 200, r.text
    _check("escalation-result.schema.json", r.json())
    case = SessionLocal().query(Case).filter_by(number=r.json()["case_id"]).one()
    assert case.title.startswith("[Vuln]") and case.client.platform_client_id == "plat-rb"
    # a second finding naming that case attaches instead of opening another
    r2 = client.post("/api/ir-cases", json=_payload(case_ref=r.json()["case_id"], title="XSS"), headers=_bearer())
    assert r2.json()["linked"] is True and SessionLocal().query(Case).count() == 1
    # the case API carries the platform id so the control plane can match it
    rows = client.get("/api/ir-cases", params={"platform_client_id": "plat-rb"}, headers=_bearer()).json()
    assert len(rows) == 1 and rows[0]["client"]["platform_client_id"] == "plat-rb"
    assert client.get("/api/ir-cases", params={"status": "open"}, headers=_bearer()).json()
    assert client.get("/api/ir-cases", params={"platform_client_id": "other"}, headers=_bearer()).json() == []


def test_title_only_payload_still_titles_the_case(client):
    p = _payload()
    del p["summary"]  # an older caller that sends title but not summary
    r = client.post("/api/ir-cases", json=p, headers=_bearer())
    assert r.status_code == 200
    assert SessionLocal().query(Case).one().title.startswith("[Vuln]")


def test_source_module_local_id_never_matches_a_hub_client(client):
    db = SessionLocal()
    other = Client(name="Someone Else", platform_client_id="plat-other")
    db.add(other); db.commit()
    # the module's own client_id happens to equal a hub client's primary key
    p = _payload(client_id=other.id, pid="plat-rb")
    r = client.post("/api/ir-cases", json=p, headers=_bearer())
    case = SessionLocal().query(Case).filter_by(number=r.json()["case_id"]).one()
    assert case.client.platform_client_id == "plat-rb" and case.client_id != other.id


def test_findings_pull_asks_for_active(fresh_db):
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, json=[_finding("dark-web-monitoring", "plat-rb", "Riverbend Credit Union", "leak")])
    res = findings_mod.pull_all([{"name": "dark-web-monitoring", "base_url": "http://dark-web-monitoring:8000",
                                  "token": "t"}], transport=httpx.MockTransport(handler), force=True)
    assert seen["params"]["status"] == "active"
    assert res["findings"] and res["sources"][0]["reachable"]
