"""Streaming detection: vendor detections upserted by vendor id, Sigma single-event
grouping, Sigma thresholds with distinct counts, and the finding contract MDR reads."""
import json
from pathlib import Path

import jsonschema
from sqlalchemy import select

from app import pipeline, stream
from app.db import Connector, Detection, SessionLocal, SigmaRule
from helpers import bearer, hub_transport, make_client, make_connector, route, signin

FIX = Path(__file__).parent / "fixtures"
SCHEMA = json.loads((Path(__file__).resolve().parents[3] / "docs/contracts/finding.schema.json").read_text())


def _ingest(conn, records):
    db = SessionLocal()
    try:
        return pipeline.ingest_records(db, db.get(Connector, conn.id), records)
    finally:
        db.close()


def _run():
    db = SessionLocal()
    try:
        return stream.run(db)
    finally:
        db.close()


def _audit_role(i, role="Global Administrator", at="2026-10-19T12:00:00Z"):
    return {"id": f"aud-{i}", "activityDateTime": at, "activityDisplayName": "Add member to role",
            "category": "RoleManagement", "result": "success", "loggedByService": "Core Directory",
            "initiatedBy": {"user": {"userPrincipalName": "attacker@acme.example", "id": "u-att",
                                     "ipAddress": "198.51.100.66"}},
            "targetResources": [{"type": "User", "id": "u-bob", "userPrincipalName": "bob@acme.example",
                                 "modifiedProperties": [{"displayName": "Role.DisplayName", "oldValue": None,
                                                         "newValue": f'"{role}"'}]}]}


def test_vendor_alert_becomes_one_detection_updated_in_place(fresh_db):
    c = make_client()
    conn = make_connector(c, source="crowdstrike_alerts")
    rec = json.loads((FIX / "crowdstrike_alerts" / "epp_powershell_new.json").read_text())
    _ingest(conn, [rec])
    assert _run()["vendor_new"] == 1
    closed = json.loads((FIX / "crowdstrike_alerts" / "credential_dump_closed.json").read_text())
    _ingest(conn, [closed])
    _run()
    dets = SessionLocal().execute(select(Detection).where(Detection.kind == "vendor")).scalars().all()
    assert len(dets) == 2 and all(d.tenant == "plat-acme" for d in dets)
    assert any(d.status == "closed" for d in dets)
    assert all(d.mitre for d in dets)


def test_sigma_rule_fires_once_per_subject_and_folds_repeats(fresh_db):
    conn = make_connector(make_client(), source="entra_audit")
    _ingest(conn, [_audit_role(1), _audit_role(2, at="2026-10-19T12:10:00Z"),
                   _audit_role(3, role="Reports Reader")])
    summ = _run()
    assert summ["sigma_new"] == 1
    d = SessionLocal().execute(select(Detection).where(Detection.kind == "sigma")).scalar_one()
    assert d.rule_title == "Entra ID privileged role assigned" and d.count == 2 and d.severity == "high"
    assert "T1098.003" in d.mitre
    assert SessionLocal().get(SigmaRule, d.rule_id).hits_total == 2


def test_password_spray_threshold_counts_distinct_users(fresh_db):
    conn = make_connector(make_client())
    same_user = [signin(i, user="alice@acme.example", ip="203.0.113.9", ok=False,
                        at=f"2026-10-19T12:0{i % 10}:00Z") for i in range(12)]
    _ingest(conn, same_user)
    _run()
    assert SessionLocal().execute(select(Detection).where(Detection.kind == "sigma")).first() is None
    spray = [signin(100 + i, user=f"user{i}@acme.example", ip="203.0.113.9", ok=False,
                    at=f"2026-10-19T12:05:{i:02d}Z") for i in range(10)]
    _ingest(conn, spray)
    _run()
    d = SessionLocal().execute(select(Detection).where(Detection.kind == "sigma")).scalar_one()
    assert d.group_key == "203.0.113.9" and d.count >= 10 and "Password spray" in d.title


def test_detection_pass_is_incremental(fresh_db):
    conn = make_connector(make_client(), source="entra_audit")
    _ingest(conn, [_audit_role(1)])
    assert _run()["events"] == 1
    assert _run()["events"] == 0


def test_findings_api_serves_contract_shape_with_proof_links(client, monkeypatch):
    conn = make_connector(make_client(), source="entra_audit")
    _ingest(conn, [_audit_role(1)])
    _run()
    db = SessionLocal()
    pipeline.seal(db)
    db.close()
    rows = client.get("/api/findings", headers=bearer()).json()
    assert len(rows) == 1
    f = rows[0]
    jsonschema.validate(f, SCHEMA)
    assert f["module"] == "ingest" and f["type"] == "sigma" and f["reason"] == "entra"
    assert f["subject"]["platform_client_id"] == "plat-acme"
    ev = f["evidence"][0]
    assert ev["sealed"] is True and ev["storage_uri"].endswith(f"/api/events/{ev['id']}/proof")
    proof = client.get(f"/api/events/{ev['id']}/proof?raw=true", headers=bearer()).json()
    from app import receipts
    assert receipts.verify_proof(proof, proof.pop("raw"))["ok"]
    assert client.get("/api/findings?platform_client_id=plat-other", headers=bearer()).json() == []
    assert client.get("/api/findings?status=bogus", headers=bearer()).status_code == 400


def test_escalation_carries_the_finding_and_links_on_repeat(client, monkeypatch):
    from app import hub
    from app.config import settings
    conn = make_connector(make_client(), source="entra_audit")
    _ingest(conn, [_audit_role(1)])
    _run()
    did = SessionLocal().execute(select(Detection)).scalar_one().id
    monkeypatch.setattr(settings, "platform_hub_url", "http://hub")
    monkeypatch.setattr(settings, "platform_hub_token", "hubtok")
    cap = {}
    route(monkeypatch, hub, hub_transport(cap))
    r1 = client.post(f"/api/findings/{did}/escalate", headers=bearer()).json()
    r2 = client.post(f"/api/findings/{did}/escalate", headers=bearer()).json()
    assert r1 == {"escalated": True, "case": "VCD-IR-2026-901", "linked": False}
    assert r2["linked"] is True
    p = cap["payloads"][0]
    assert p["source_module"] == "ingest" and p["platform_client_id"] == "plat-acme"
    assert cap["auth"] == "Bearer hubtok"
    jsonschema.validate(p["finding"], SCHEMA)
