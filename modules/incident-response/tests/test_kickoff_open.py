"""POST /api/ir-cases/open: a Project Management kickoff opens a case on the
five-workstream template with no finding card, and a retried kickoff gets the same
case back instead of a second one."""
from app import auth
from app.db import Case, CaseUpdate, SessionLocal


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_kickoff_opens_one_case_and_is_idempotent(client):
    body = {"client": "Riverbend CU", "title": "BEC: CFO mailbox", "severity": "critical",
            "incident_type": "bec", "lead": "dan@vendettacd.io", "source_module": "project-management"}
    r = client.post("/api/ir-cases/open", json=body, headers=_bearer())
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["existing"] is False and first["case_id"].startswith("VCD-IR-")
    again = client.post("/api/ir-cases/open", json=body, headers=_bearer()).json()
    assert again == {**first, "existing": True}
    db = SessionLocal()
    case = db.get(Case, first["id"])
    assert case.origin == "kickoff" and case.severity == "critical" and case.lead == "dan@vendettacd.io"
    assert len(case.workstreams) == 5
    assert not db.query(CaseUpdate).filter_by(case_id=case.id, kind="finding").count()
    db.close()


def test_open_requires_token_and_title(client):
    assert client.post("/api/ir-cases/open", json={"client": "X", "title": "t"}).status_code in (401, 403)
    assert client.post("/api/ir-cases/open", json={"client": "X"}, headers=_bearer()).status_code == 400
