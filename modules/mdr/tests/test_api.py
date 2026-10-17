"""Service API beyond findings: suppressions, coverage, module manifest, rules; and
the admin-only rule editing with versions and per-client overrides."""
import datetime as dt

from app.db import Rule, RuleOverride, RuleVersion, SessionLocal, Suppression
from helpers import as_user, bearer, make_client


def test_post_suppression_contract(client):
    make_client()
    body = {"platform_client_id": "plat-acme", "tool": "huntress", "title_contains": "Approved RMM",
            "host": "ACME-DC01", "reason": "Rejected three times by the SOC", "days": 14, "created_by": "sabine"}
    r = client.post("/api/suppressions", json=body, headers=bearer("sabine"))
    assert r.status_code == 200, r.text
    out = r.json()
    assert set(out) == {"id", "expires_at"}
    s = SessionLocal().get(Suppression, out["id"])
    assert s.created_by == "sabine" and s.tool == "huntress" and s.host == "ACME-DC01"
    exp = dt.datetime.fromisoformat(out["expires_at"])
    assert 13 <= (exp - dt.datetime.now(dt.timezone.utc)).days <= 14


def test_post_suppression_validation(client):
    make_client()
    base = {"platform_client_id": "plat-acme", "tool": "huntress", "reason": "x", "days": 10}
    assert client.post("/api/suppressions", json={**base, "platform_client_id": "nope"},
                       headers=bearer()).status_code == 404
    assert client.post("/api/suppressions", json={**base, "days": 0}, headers=bearer()).status_code == 400
    assert client.post("/api/suppressions", json={**base, "days": 91}, headers=bearer()).status_code == 400
    assert client.post("/api/suppressions", json={**base, "reason": ""}, headers=bearer()).status_code == 400
    assert client.post("/api/suppressions", json={**base, "tool": ""}, headers=bearer()).status_code == 400
    assert client.post("/api/suppressions", json=base).status_code == 401


def test_get_suppressions_filter_and_activity(client):
    a = make_client()
    b = make_client(name="Bravo", pid="plat-bravo", domains="bravo.example")
    db = SessionLocal()
    now = dt.datetime.now(dt.timezone.utc)
    db.add_all([Suppression(client_id=a.id, platform_client_id="plat-acme", tool="aws", reason="r",
                            expires_at=now + dt.timedelta(days=3), created_by="t"),
                Suppression(client_id=a.id, platform_client_id="plat-acme", host="old", reason="r",
                            expires_at=now - dt.timedelta(days=3), created_by="t"),
                Suppression(client_id=b.id, platform_client_id="plat-bravo", tool="entra", reason="r",
                            expires_at=now + dt.timedelta(days=3), created_by="t")])
    db.commit()
    rows = client.get("/api/suppressions", params={"platform_client_id": "plat-acme"}, headers=bearer()).json()
    assert len(rows) == 2 and {r["active"] for r in rows} == {True, False}
    assert all(r["platform_client_id"] == "plat-acme" and r["client"] == "Acme Corp" for r in rows)
    assert {"match", "reason", "expires_at", "created_by", "created_at", "hits"} <= set(rows[0])
    assert len(client.get("/api/suppressions", headers=bearer()).json()) == 3


def test_suppressions_page_sections(admin):
    a = make_client()
    db = SessionLocal()
    now = dt.datetime.now(dt.timezone.utc)
    db.add_all([Suppression(client_id=a.id, platform_client_id="plat-acme", tool="aws", reason="long one",
                            expires_at=now + dt.timedelta(days=20), created_by="t"),
                Suppression(client_id=a.id, platform_client_id="plat-acme", tool="aws", reason="soon one",
                            expires_at=now + dt.timedelta(days=2), created_by="t"),
                Suppression(client_id=a.id, platform_client_id="plat-acme", tool="aws", reason="gone one",
                            expires_at=now - dt.timedelta(days=2), created_by="t")])
    db.commit()
    page = admin.get("/suppressions").text
    assert page.index("long one") < page.index("soon one") < page.index("gone one")
    gone = SessionLocal().query(Suppression).filter_by(reason="gone one").one()
    admin.post(f"/suppressions/{gone.id}/review", data={"renew_days": 0})
    assert SessionLocal().get(Suppression, gone.id).reviewed_by == "admin"
    long = SessionLocal().query(Suppression).filter_by(reason="long one").one()
    admin.post(f"/suppressions/{long.id}/expire")
    assert not SessionLocal().get(Suppression, long.id).is_active()


def test_coverage_api(client):
    body = client.get("/api/coverage", headers=bearer()).json()
    names = [t["name"] for t in body["tactics"]]
    assert names[0] == "Reconnaissance" and names[-1] == "Impact" and len(names) == 14
    impact = next(t for t in body["tactics"] if t["name"] == "Impact")
    tech = {t["id"]: t for t in impact["techniques"]}
    assert "T1486" in tech and "ransomware-behavior" in tech["T1486"]["rules"]
    cred = next(t for t in body["tactics"] if t["name"] == "Credential Access")
    assert cred["covered"] and cred["enabled_rules"] >= 4
    assert body["rules"] >= 10 and body["tactics_covered"] >= 8
    assert "host-signal-burst" in body["correlation_rules"]


def test_module_manifest(client):
    body = client.get("/api/module", headers=bearer()).json()
    assert body["module"] == "mdr" and body["enabled"] is True and body["finding_types"] == ["investigation"]
    assert body["readiness"]["module"] == "mdr"
    assert body["readiness"]["integrations"]["kind"] == "signal-pull"
    assert "/api/metrics" in body["endpoints"] and body["counts"]["open"] == 0
    assert client.get("/api/module").status_code == 401


def test_module_disabled(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "module_enabled", False)
    assert client.get("/api/module", headers=bearer()).json()["enabled"] is False
    assert client.get("/").status_code == 503


def test_rules_seeded_with_versions(client):
    rules = client.get("/api/rules", headers=bearer()).json()
    assert len(rules) >= 10 and all(r["version"] == 1 for r in rules)
    assert SessionLocal().query(RuleVersion).filter_by(kind="seed").count() == len(rules)


def _form(rule, **changes):
    data = {"name": rule.name, "description": rule.description, "severity": rule.severity,
            "tools": ", ".join(rule.match.get("tools", [])), "types": ", ".join(rule.match.get("types", [])),
            "title_any": "\n".join(rule.match.get("title_any", [])),
            "min_severity": rule.match.get("min_severity", "low"),
            "group_by": rule.correlation.get("group_by", "host"),
            "window_minutes": rule.correlation.get("window_minutes", 60),
            "threshold": rule.correlation.get("threshold", 1), "mitre": ", ".join(rule.mitre),
            "response": rule.response, "enabled": "true", "note": "tuning"}
    data.update(changes)
    return data


def test_admin_edits_rule_and_version_is_recorded(admin):
    r = SessionLocal().get(Rule, "suspicious-powershell")
    resp = admin.post("/rules/suspicious-powershell", data=_form(r, severity="critical", note="seen in the wild"),
                      follow_redirects=False)
    assert "msg=" in resp.headers["location"]
    r = SessionLocal().get(Rule, "suspicious-powershell")
    assert r.version == 2 and r.severity == "critical" and r.updated_by == "admin"
    v = SessionLocal().query(RuleVersion).filter_by(rule_key="suspicious-powershell", version=2).one()
    assert v.kind == "edit" and v.changed_by == "admin" and v.note == "seen in the wild"
    assert v.snapshot["severity"] == "critical"


def test_rule_edit_validation(admin):
    r = SessionLocal().get(Rule, "suspicious-powershell")
    for bad in ({"mitre": "1059"}, {"tools": "splunk"}, {"threshold": "0"}, {"group_by": "planet"}):
        resp = admin.post("/rules/suspicious-powershell", data=_form(r, **bad), follow_redirects=False)
        assert "err=" in resp.headers["location"], bad
    resp = admin.post("/rules/suspicious-powershell", data=_form(r, tools="", types="", title_any="", threshold="1"),
                      follow_redirects=False)
    assert "err=" in resp.headers["location"]
    assert SessionLocal().get(Rule, "suspicious-powershell").version == 1


def test_analyst_reads_rules_but_cannot_edit(client):
    as_user(client, "sam@vendettacd.io", "analyst")
    assert client.get("/rules/suspicious-powershell").status_code == 200
    r = SessionLocal().get(Rule, "suspicious-powershell")
    assert client.post("/rules/suspicious-powershell", data=_form(r, severity="low"),
                       follow_redirects=False).status_code == 403
    a = make_client()
    assert client.post("/rules/suspicious-powershell/overrides", data={"client_id": a.id, "disabled": "true"},
                       follow_redirects=False).status_code == 403


def test_admin_override_and_remove(admin):
    a = make_client()
    admin.post("/rules/ransomware-behavior/overrides", data={"client_id": a.id, "severity": "high", "note": "lab"})
    o = SessionLocal().query(RuleOverride).one()
    assert o.severity == "high" and not o.disabled and o.updated_by == "admin"
    assert SessionLocal().query(RuleVersion).filter_by(rule_key="ransomware-behavior", kind="override").count() == 1
    # neither disable nor severity is refused
    resp = admin.post("/rules/ransomware-behavior/overrides", data={"client_id": a.id}, follow_redirects=False)
    assert "err=" in resp.headers["location"]
    admin.post(f"/rules/ransomware-behavior/overrides/{o.id}/delete")
    assert SessionLocal().query(RuleOverride).count() == 0
    assert SessionLocal().query(RuleVersion).filter_by(rule_key="ransomware-behavior", kind="override").count() == 2
