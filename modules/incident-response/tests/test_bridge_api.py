"""Case operations a chat bridge (the Slack responder) drives through the service
API. The bridge sends its own bearer token and names the person it acts for in
X-Vendetta-On-Behalf-Of; every entry must carry that person, and the header must
mean nothing without the token."""
from app import auth
from app.db import AuditLog, Case, CaseUpdate, Client, SessionLocal

PERSON = "dan@vendettacd.io"


def _h(person: str = PERSON, actor: str = "slack"):
    h = {"Authorization": f"Bearer {auth.api_token()}", "X-Vendetta-Actor": actor}
    if person:
        h["X-Vendetta-On-Behalf-Of"] = person
    return h


def _declare(client, severity="critical"):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", platform_client_id="plat-rb")
    db.add(c)
    db.commit()
    r = client.post("/api/ir-cases/declare", headers=_h(),
                    json={"platform_client_id": "plat-rb", "description": "Ransom note on FS01", "severity": severity})
    assert r.status_code == 200, r.text
    return r.json()


def test_declare_names_the_person_and_returns_a_number(client):
    out = _declare(client)
    case = SessionLocal().query(Case).filter_by(number=out["case_id"]).one()
    assert case.severity == "critical" and case.origin == "declared"
    row = SessionLocal().query(AuditLog).filter_by(action="case.declare").one()
    assert row.actor == f"{PERSON} via slack"


def test_detail_by_number_or_id_carries_tasks_and_updates(client):
    out = _declare(client)
    by_num = client.get(f"/api/ir-cases/{out['case_id'].lower()}", headers=_h()).json()
    by_id = client.get(f"/api/ir-cases/{out['id']}", headers=_h()).json()
    assert by_num["number"] == by_id["number"] == out["case_id"]
    assert by_num["tasks"] and by_num["updates"] and "link" in by_num
    assert client.get("/api/ir-cases/VCD-IR-1999-1", headers=_h()).status_code == 404


def test_note_is_attributed_internal_by_default_and_keeps_its_source(client):
    out = _declare(client)
    r = client.post(f"/api/ir-cases/{out['case_id']}/updates", headers=_h(),
                    json={"note": "Beacon to 203.0.113.9 every 60s from FS01",
                          "workstream": "Forensics and Analysis", "source": "https://x.slack.com/archives/C1/p1"})
    assert r.status_code == 200, r.text
    u = SessionLocal().query(CaseUpdate).filter_by(id=r.json()["update_id"]).one()
    assert u.actor == f"{PERSON} via slack" and u.internal_only is True
    assert u.workstream == "Forensics and Analysis" and u.payload["source"].startswith("https://")
    assert u.content_hash  # the entry is on the signed chain
    assert client.get(f"/api/cases/{out['id']}/chain/verify", headers=_h()).json()["ok"] is True


def test_on_behalf_header_means_nothing_without_the_token(client):
    out = _declare(client)
    r = client.post(f"/api/ir-cases/{out['case_id']}/updates",
                    headers={"X-Vendetta-On-Behalf-Of": PERSON}, json={"note": "spoof"})
    assert r.status_code in (401, 403)


def test_garbage_on_behalf_falls_back_to_the_bridge(client):
    out = _declare(client)
    r = client.post(f"/api/ir-cases/{out['case_id']}/updates", headers=_h(person="not an email <script>"),
                    json={"note": "x"})
    u = SessionLocal().query(CaseUpdate).filter_by(id=r.json()["update_id"]).one()
    assert u.actor == "api:slack"


def test_status_details_tasks_and_moves(client):
    out = _declare(client, severity="high")
    ref = out["case_id"]
    assert client.post(f"/api/ir-cases/{ref}/status", headers=_h(), json={"status": "bogus"}).status_code == 400
    r = client.post(f"/api/ir-cases/{ref}/status", headers=_h(), json={"status": "contained"}).json()
    assert r == {"ok": True, "case_id": ref, "from": "open", "status": "contained"}

    r = client.post(f"/api/ir-cases/{ref}/details", headers=_h(),
                    json={"severity": "critical", "lead": "Jordan Snook"}).json()
    assert len(r["changes"]) == 2
    assert client.post(f"/api/ir-cases/{ref}/details", headers=_h(), json={"severity": "urgent"}).status_code == 400

    r = client.post(f"/api/ir-cases/{ref}/tasks", headers=_h(),
                    json={"workstream": "Scoping and Containment", "title": "Isolate FS01", "owner": PERSON})
    assert r.status_code == 200, r.text
    tid = r.json()["task"]["id"]
    assert client.post(f"/api/ir-cases/{ref}/tasks", headers=_h(),
                       json={"workstream": "Nope", "title": "x"}).status_code == 400
    r = client.post(f"/api/ir-cases/{ref}/tasks/{tid}/move", headers=_h(), json={"status": "done"}).json()
    assert r["moved"] is True and r["task"]["status"] == "done"

    case = SessionLocal().query(Case).filter_by(number=ref).one()
    assert case.status == "contained" and case.severity == "critical" and case.lead == "Jordan Snook"
    rows = SessionLocal().query(CaseUpdate).filter_by(case_id=case.id).all()
    status_row = next(u for u in rows if u.kind == "status" and u.note.startswith("Status open"))
    card_rows = [u for u in rows if u.kind == "task" and "Isolate FS01" in u.note]
    assert status_row.actor == f"{PERSON} via slack" and status_row.internal_only is False
    assert card_rows and all(u.actor == f"{PERSON} via slack" for u in card_rows)


def test_viewer_session_cannot_write_through_the_bridge_routes(client):
    from app import auth as a
    out = _declare(client)
    from app.db import User
    db = SessionLocal()
    db.add(User(email="v@vendettacd.io", role="viewer"))
    db.commit()
    client.cookies.set(a.COOKIE, a.make_session("v@vendettacd.io"))
    r = client.post(f"/api/ir-cases/{out['case_id']}/updates", json={"note": "x"})
    assert r.status_code == 403
