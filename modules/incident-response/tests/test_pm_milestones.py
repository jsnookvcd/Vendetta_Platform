"""POST /api/ir-cases/{ref}/milestones: Project Management publishes a case's
client-visible milestones; the portal shows them and a newly reached one lands on
the signed timeline as a client-visible entry, exactly once."""
from app import auth, evidence
from app.db import CaseUpdate, Client, SessionLocal, User, case_chain_records, open_case


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}", "X-Vendetta-Actor": "project-management"}


def _ms(status_contained="in_progress"):
    return {"source_module": "project-management", "engagement_code": "VCD-IR-2026-001", "milestones": [
        {"key": "m1", "title": "Environment contained", "workstream": "Scoping and Containment",
         "status": status_contained, "due_on": "2026-10-22", "completed_on": None},
        {"key": "m2", "title": "Final report delivered", "workstream": "Notification and Legal",
         "status": "planned", "due_on": "2026-11-10", "completed_on": None}]}


def _case():
    db = SessionLocal()
    c = Client(name="Riverbend CU")
    db.add(c); db.commit()
    return c, open_case(db, c, "Ransomware on file server")


def test_publish_by_number_and_portal_shows_them(client):
    c, case = _case()
    r = client.post(f"/api/ir-cases/{case.number}/milestones", json=_ms(), headers=_bearer())
    assert r.status_code == 200 and r.json() == {"ok": True, "case": case.number, "milestones": 2,
                                                 "new_completions": 0}
    db = SessionLocal()
    db.add(User(email="it@riverbend.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@riverbend.example"))
    page = client.get(f"/portal/cases/{case.id}").text
    assert "Environment contained" in page and "target 2026-11-10" in page


def test_reaching_a_milestone_writes_one_signed_client_entry(client):
    _c, case = _case()
    client.post(f"/api/ir-cases/{case.id}/milestones", json=_ms(), headers=_bearer())
    done = _ms("done")
    done["milestones"][0]["completed_on"] = "2026-10-21"
    assert client.post(f"/api/ir-cases/{case.number}/milestones", json=done, headers=_bearer()).json()[
        "new_completions"] == 1
    assert client.post(f"/api/ir-cases/{case.number}/milestones", json=done, headers=_bearer()).json()[
        "new_completions"] == 0
    db = SessionLocal()
    entries = db.query(CaseUpdate).filter_by(case_id=case.id, kind="status").all()
    assert [e.note for e in entries] == ["Milestone reached: Environment contained"]
    assert entries[0].internal_only is False and entries[0].actor == "api:project-management"
    assert evidence.verify_chain(case_chain_records(db, case.id))["ok"]


def test_requires_the_service_token_and_a_real_case(client):
    _c, case = _case()
    assert client.post(f"/api/ir-cases/{case.number}/milestones", json=_ms()).status_code == 401
    assert client.post("/api/ir-cases/VCD-IR-1999-1/milestones", json=_ms(), headers=_bearer()).status_code == 404
    bad = client.post(f"/api/ir-cases/{case.number}/milestones", json={"milestones": "x"}, headers=_bearer())
    assert bad.status_code == 400
