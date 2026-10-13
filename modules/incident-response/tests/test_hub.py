"""IR Hub behaviour: case numbering, workstreams, escalation contract, portal, privilege, enablement."""
from app import auth
from app.config import WORKSTREAMS, settings
from app.db import Case, Client, Retainer, SessionLocal, User, open_case

# The payload shape the dark web module (and every module) sends via platform.escalate.
DW_PAYLOAD = {
    "source_module": "dark-web-monitoring",
    "client_id": "dw-client-id-not-in-hub",
    "case_ref": "",
    "severity": "high",
    "summary": "Dark web credential finding: combo dump",
    "workstream": "Forensics and Analysis",
    "finding": {
        "id": "hit123", "module": "dark-web-monitoring", "platform": "Vendetta Platform",
        "subject": {"client_id": "dw-client-id-not-in-hub", "client": "Riverbend Credit Union", "case_ref": ""},
        "type": "paste", "reason": "credential", "severity": "high", "status": "reviewing",
        "title": "combo dump", "matched": "jsmith@riverbendcu.org",
        "evidence": [{"id": "e1", "sha256": "ab" * 32, "captured_at": "2026-10-12T20:00:00Z", "storage_uri": "s3://x"}],
        "workstream": "Forensics and Analysis",
    },
}


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_case_numbers_are_firm_wide_and_sequential(fresh_db):
    db = SessionLocal()
    a, b = Client(name="Alpha"), Client(name="Bravo")
    db.add_all([a, b]); db.commit()
    c1 = open_case(db, a, "first")
    c2 = open_case(db, b, "second")
    c3 = open_case(db, a, "third")
    assert [c1.seq, c2.seq, c3.seq] == [settings.case_seq_start, settings.case_seq_start + 1, settings.case_seq_start + 2]
    assert c1.number == f"{settings.case_prefix}-{settings.case_year}-{settings.case_seq_start}"
    assert "Alpha" not in c1.number  # client never in the number


def test_case_opens_with_five_workstreams(fresh_db):
    db = SessionLocal()
    c = Client(name="Alpha"); db.add(c); db.commit()
    case = open_case(db, c, "x")
    assert [w.name for w in case.workstreams] == WORKSTREAMS
    assert case.workstreams[0].status == "in_progress"
    assert all(w.status == "not_started" for w in case.workstreams[1:])


def test_escalation_contract_opens_case_and_resolves_client_by_name(client):
    db = SessionLocal()
    db.add(Client(name="Riverbend Credit Union")); db.commit()
    r = client.post("/api/ir-cases", json=DW_PAYLOAD, headers=_bearer())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["linked"] is False and body["case_id"].startswith(settings.case_prefix)
    db = SessionLocal()
    case = db.query(Case).filter_by(number=body["case_id"]).one()
    assert case.client.name == "Riverbend Credit Union" and case.origin == "escalated"
    assert case.source_module == "dark-web-monitoring"
    f = [u for u in case.updates if u.kind == "finding"][0]
    assert f.workstream == "Forensics and Analysis" and f.payload["finding"]["matched"] == "jsmith@riverbendcu.org"
    assert db.query(Client).count() == 1  # matched existing client, did not duplicate


def test_escalation_links_to_open_case_and_only_raises_severity(client):
    r1 = client.post("/api/ir-cases", json=DW_PAYLOAD, headers=_bearer()).json()
    linked_payload = dict(DW_PAYLOAD, case_ref=r1["case_id"], severity="critical")
    r2 = client.post("/api/ir-cases", json=linked_payload, headers=_bearer()).json()
    assert r2["linked"] is True and r2["case_id"] == r1["case_id"]
    lower = dict(DW_PAYLOAD, case_ref=r1["case_id"], severity="low")
    client.post("/api/ir-cases", json=lower, headers=_bearer())
    db = SessionLocal()
    assert db.query(Case).count() == 1
    case = db.query(Case).one()
    assert case.severity == "critical"  # raised by escalation, not lowered
    assert len([u for u in case.updates if u.kind == "finding"]) == 3


def test_escalation_for_unknown_client_creates_it(client):
    r = client.post("/api/ir-cases", json=DW_PAYLOAD, headers=_bearer())
    assert r.status_code == 200
    assert SessionLocal().query(Client).filter_by(name="Riverbend Credit Union").count() == 1


def test_escalated_case_gets_retainer_lead(client):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union"); db.add(c); db.commit()
    db.add(Retainer(client_id=c.id, active=True, tier="Core", named_responders="A. Reyes, J. Snook")); db.commit()
    body = client.post("/api/ir-cases", json=DW_PAYLOAD, headers=_bearer()).json()
    assert SessionLocal().query(Case).filter_by(number=body["case_id"]).one().lead == "A. Reyes"


def test_escalation_requires_auth(client):
    assert client.post("/api/ir-cases", json=DW_PAYLOAD).status_code == 401


def test_declare_pages_and_assigns_retainer_lead(admin):
    db = SessionLocal()
    c = Client(name="Alpha"); db.add(c); db.commit()
    db.add(Retainer(client_id=c.id, tier="GetZero Core", active=True, named_responders="Dan Baker, Jordan Snook")); db.commit()
    r = admin.post("/declare", data={"client_id": c.id, "description": "Ransom note on file server", "severity": "critical"}, follow_redirects=False)
    assert r.status_code == 302
    case = SessionLocal().query(Case).one()
    assert case.origin == "declared" and case.lead == "Dan Baker" and case.severity == "critical"


def _portal_session(client, email, client_obj):
    db = SessionLocal()
    db.add(User(email=email, role="client", client_id=client_obj.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_portal_is_scoped_and_declare_needs_retainer(client):
    db = SessionLocal()
    mine, other = Client(name="Mine"), Client(name="Other")
    db.add_all([mine, other]); db.commit()
    my_case = open_case(db, mine, "my incident")
    other_case = open_case(db, other, "not mine")
    _portal_session(client, "cfo@mine.org", mine)
    r = client.get("/portal")
    assert r.status_code == 200 and "my incident" in r.text and "not mine" not in r.text
    assert client.get(f"/portal/cases/{other_case.id}").status_code == 404
    assert client.get("/cases", follow_redirects=False).headers["location"] == "/portal"
    # no retainer: declaring is refused
    assert client.post("/portal/declare", data={"description": "help"}).status_code == 403
    db = SessionLocal()
    db.add(Retainer(client_id=mine.id, active=True, tier="Core")); db.commit()
    r = client.post("/portal/declare", data={"description": "help"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/portal/cases/")
    assert my_case.id  # sanity


def test_portal_hides_internal_and_privileged_detail(client):
    db = SessionLocal()
    c = Client(name="Mine"); db.add(c); db.commit()
    case = open_case(db, c, "matter")
    _portal_session(client, "it@mine.org", c)
    admin_note = "INTERNAL: suspect insider, do not share"
    db = SessionLocal()
    from app.db import CaseUpdate
    db.add(CaseUpdate(case_id=case.id, note=admin_note, internal_only=True))
    db.add(CaseUpdate(case_id=case.id, note="Shared: containment underway", internal_only=False))
    db.commit()
    r = client.get(f"/portal/cases/{case.id}")
    assert "containment underway" in r.text and admin_note not in r.text
    db = SessionLocal(); cs = db.get(Case, case.id); cs.privileged = True; db.commit()
    r = client.get(f"/portal/cases/{case.id}")
    assert "containment underway" not in r.text and "direction of counsel" in r.text


def test_page_carries_case_link(fresh_db, monkeypatch):
    from app import notify
    sent = {}

    class _Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, json, timeout):
        sent["card"] = json
        return _Resp()

    monkeypatch.setattr(notify.httpx, "post", fake_post)
    monkeypatch.setattr(settings, "teams_webhook_url", "https://example.invalid/hook")
    monkeypatch.setattr(settings, "public_url", "https://ir.example.com/")
    db = SessionLocal()
    c = Client(name="Alpha"); db.add(c); db.commit()
    case = open_case(db, c, "x", severity="critical")
    assert notify.page_new_case(case) == {"teams": "sent"}
    content = sent["card"]["attachments"][0]["content"]
    assert content["actions"][0]["url"] == f"https://ir.example.com/cases/{case.id}"
    assert case.number in content["body"][0]["text"] and "CRITICAL" in content["body"][0]["text"]


def test_module_on_off(client):
    settings.module_enabled = False
    try:
        assert client.get("/").status_code == 503
        assert client.get("/api/module", headers=_bearer()).json()["enabled"] is False
        assert client.get("/healthz").status_code == 200
    finally:
        settings.module_enabled = True
    assert client.get("/login").status_code == 200
