"""Cross-module contracts: what MDR serves at /api/findings and sends to the hub must
match docs/contracts/*.schema.json. The hub is mocked; the payload it receives is
validated against the schema, and re-escalation names the stored case."""
import datetime as dt
import json
import os

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from app import hub
from app.config import settings
from app.db import Investigation, SessionLocal, timeline
from helpers import bearer, finding, hub_transport, ingest, make_client, route

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


def _setup(now):
    make_client()
    make_client(name="Bravo", pid="plat-bravo", domains="bravo.example")
    ingest([finding(fid="a1", at=now - dt.timedelta(minutes=2)),
            finding(fid="b1", pid="plat-bravo", client="Bravo", tool="entra", kind="incident",
                    title="Impossible travel for cfo@bravo.example", host="cfo@bravo.example", at=now)], now=now)
    return SessionLocal().query(Investigation).filter_by(platform_client_id="plat-acme").one()


def test_findings_match_shared_schema_with_mdr_extras(client, now, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://mdr.vendettacyber.com")
    inv = _setup(now)
    rows = client.get("/api/findings", headers=bearer()).json()
    assert len(rows) == 2
    for row in rows:
        _check("finding.schema.json", row)
        assert row["module"] == "mdr" and row["type"] == "investigation"
        for extra in ("native_status", "verdict", "mitre", "opened_at", "acknowledged_at", "contained_at",
                      "response", "rule", "signals"):
            assert extra in row
    acme = next(r for r in rows if r["id"] == inv.id)
    assert acme["status"] == "new" and acme["native_status"] == "new" and acme["verdict"] == "pending"
    assert acme["mitre"] == ["T1486"] and acme["rule"] == "ransomware-behavior" and acme["signals"] == 1
    assert acme["response"] == {"action": "isolate_host", "host": "ACME-WS01", "alert_ref": "a1"}
    assert acme["acknowledged_at"] is None and acme["contained_at"] is None
    assert acme["url"] == f"https://mdr.vendettacyber.com/investigations/{inv.id}"
    assert acme["subject"]["platform_client_id"] == "plat-acme"


def test_findings_filters(client, now):
    inv = _setup(now)
    get = lambda **p: client.get("/api/findings", params=p, headers=bearer()).json()  # noqa: E731
    assert {r["id"] for r in get(platform_client_id="plat-acme")} == {inv.id}
    assert len(get(client="brav")) == 1
    assert get(platform_client_id="nope") == []
    assert len(get(status="open")) == 2 and len(get(status="new")) == 2
    db = SessionLocal()
    i = db.get(Investigation, inv.id)
    i.status, i.verdict = "closed", "false_positive"
    db.commit()
    assert len(get()) == 1 and len(get(status="all")) == 2
    closed = [r for r in get(status="closed")]
    assert closed[0]["status"] == "false_positive" and closed[0]["native_status"] == "closed"
    assert client.get("/api/findings", params={"status": "bogus"}, headers=bearer()).status_code == 400


def test_escalate_sends_contract_payload_and_reescalation_links(client, now, monkeypatch):
    inv = _setup(now)
    captured = {}
    route(monkeypatch, hub, hub_transport(captured, case="VCD-IR-2026-901"))
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    monkeypatch.setattr(settings, "platform_hub_token", "hubtok")
    r = client.post(f"/api/findings/{inv.id}/escalate", headers=bearer("sabine"))
    assert r.status_code == 200, r.text
    assert r.json() == {"escalated": True, "case": "VCD-IR-2026-901", "linked": False}
    assert captured["path"] == "/api/ir-cases" and captured["auth"] == "Bearer hubtok"
    first = captured["payloads"][0]
    _check("escalation.schema.json", first)
    assert first["workstream"] == "Scoping and Containment" and first["source_module"] == "mdr"
    assert first["case_ref"] == "" and first["platform_client_id"] == "plat-acme"
    assert first["finding"]["id"] == inv.id
    db = SessionLocal()
    i = db.get(Investigation, inv.id)
    assert i.escalated_case == "VCD-IR-2026-901" and i.status == "investigating"
    entry = [e for e in timeline(db, inv.id) if e.kind == "escalated"][0]
    assert entry.actor == "api:sabine"
    # second escalation names the stored case, and the hub links
    r = client.post(f"/api/findings/{inv.id}/escalate", headers=bearer())
    assert r.json() == {"escalated": True, "case": "VCD-IR-2026-901", "linked": True}
    second = captured["payloads"][1]
    _check("escalation.schema.json", second)
    assert second["case_ref"] == "VCD-IR-2026-901"
    assert second["finding"]["subject"]["case_ref"] == "VCD-IR-2026-901"
    _check("escalation-result.schema.json", {"case_id": "VCD-IR-2026-901", "id": "hubid", "linked": True})


def test_escalate_502_when_standalone_or_hub_fails(client, now, monkeypatch):
    inv = _setup(now)
    r = client.post(f"/api/findings/{inv.id}/escalate", headers=bearer())
    assert r.status_code == 502 and r.json()["escalated"] is False and "standalone" in r.json()["reason"]
    import httpx
    route(monkeypatch, hub, httpx.MockTransport(lambda req: httpx.Response(500)))
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    r = client.post(f"/api/findings/{inv.id}/escalate", headers=bearer())
    assert r.status_code == 502 and r.json()["reason"] == "hub HTTP 500"
    assert SessionLocal().get(Investigation, inv.id).escalated_case == ""
    assert client.post(f"/api/findings/{inv.id}/escalate").status_code == 401
    assert client.post("/api/findings/nope/escalate", headers=bearer()).status_code == 404


def test_ui_escalate(admin, now, monkeypatch):
    inv = _setup(now)
    captured = {}
    route(monkeypatch, hub, hub_transport(captured))
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    r = admin.post(f"/investigations/{inv.id}/escalate", data={"note": "ransomware confirmed"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert captured["payloads"][0]["detail"] == "ransomware confirmed"
    _check("escalation.schema.json", captured["payloads"][0])
