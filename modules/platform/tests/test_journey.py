"""The Security Journey: the service API SABINE calls (idempotent proposals, the
progress rule that only a person accepts a proposal, area validation) and the staff
controls on the client page (accept, decline, edit, move, add)."""
from app.db import AuditLog, JourneyItem, SessionLocal
from helpers import bearer, make_client, sign_in_as


def _propose(client, pid, **body):
    payload = {"title": "Enforce MFA for admins", "detail": "Three admin accounts lack MFA.", "area": "identity",
               "source_ref": "mfa:admins", **body}
    return client.post(f"/api/platform/clients/{pid}/journey", json=payload, headers=bearer("sabine"))


def test_propose_is_idempotent_on_source_ref(admin):
    c = make_client(admin)
    r = _propose(admin, c.id, due_on="2026-12-01")
    assert r.status_code == 200 and r.json()["created"] is True
    iid = r.json()["id"]
    again = _propose(admin, c.id, title="Different words, same evidence")
    assert again.json() == {"id": iid, "created": False}
    item = SessionLocal().get(JourneyItem, iid)
    assert item.status == "proposed" and item.source == "sabine" and item.due_on.isoformat() == "2026-12-01"
    assert item.title == "Enforce MFA for admins"
    # an empty source_ref never deduplicates
    a = _propose(admin, c.id, source_ref="").json()
    b = _propose(admin, c.id, source_ref="").json()
    assert a["created"] and b["created"] and a["id"] != b["id"]
    # the same source_ref on another client is a separate item
    other = make_client(admin, "Cedar Valley")
    assert _propose(admin, other.id).json()["created"] is True
    # SABINE named itself, so the audit row reads api:sabine
    assert SessionLocal().query(AuditLog).filter_by(action="journey.propose", actor="api:sabine").count() == 4


def test_propose_validation(admin):
    c = make_client(admin)
    assert _propose(admin, c.id, area="physical").status_code == 400
    assert _propose(admin, c.id, title="  ").status_code == 400
    assert _propose(admin, c.id, due_on="next week").status_code == 400
    assert _propose(admin, "no-such-client").status_code == 404
    r = admin.post(f"/api/platform/clients/{c.id}/journey", content=b"not json", headers=bearer())
    assert r.status_code == 400
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anon:
        assert anon.post(f"/api/platform/clients/{c.id}/journey", json={}).status_code == 401
        assert anon.get(f"/api/platform/clients/{c.id}/journey").status_code == 401


def test_get_journey_shape(admin):
    c = make_client(admin)
    iid = _propose(admin, c.id).json()["id"]
    out = admin.get(f"/api/platform/clients/{c.id}/journey", headers=bearer()).json()
    assert out["client"] == {"id": c.id, "name": c.name}
    item = out["items"][0]
    assert set(item) == {"id", "title", "detail", "area", "status", "due_on", "source", "source_ref", "note",
                         "created_at", "updated_at", "decided_by"}
    assert item["id"] == iid and item["due_on"] is None and item["source_ref"] == "mfa:admins"
    assert admin.get("/api/platform/clients/nope/journey", headers=bearer()).status_code == 404


def test_staff_session_on_the_api_is_attributed_staff(admin):
    c = make_client(admin)
    r = admin.post(f"/api/platform/clients/{c.id}/journey", json={"title": "Backups", "area": "data"})
    assert SessionLocal().get(JourneyItem, r.json()["id"]).source == "staff"


def test_progress_refuses_proposed_and_declined(admin):
    c = make_client(admin)
    iid = _propose(admin, c.id).json()["id"]
    url = f"/api/platform/clients/{c.id}/journey/{iid}/progress"
    r = admin.post(url, json={"status": "in_progress", "note": "started"}, headers=bearer("sabine"))
    assert r.status_code == 409
    # a person accepts it on the client page; then automation may report progress
    admin.post(f"/clients/{c.id}/journey/{iid}/accept")
    item = SessionLocal().get(JourneyItem, iid)
    assert item.status == "planned" and item.decided_by == "admin"
    r = admin.post(url, json={"status": "in_progress", "note": "2 of 3 enrolled", "source_ref": "mfa:admins"},
                   headers=bearer("sabine"))
    assert r.json() == {"id": iid, "status": "in_progress"}
    assert admin.post(url, json={"status": "planned"}, headers=bearer()).status_code == 400
    assert admin.post(url, json={"status": "declined"}, headers=bearer()).status_code == 400
    r = admin.post(url, json={"status": "done", "note": "all enrolled"}, headers=bearer())
    assert r.json()["status"] == "done"
    assert SessionLocal().get(JourneyItem, iid).note == "all enrolled"
    # declined is as final for automation as proposed
    d = _propose(admin, c.id, source_ref="edr:gaps", area="endpoint").json()["id"]
    admin.post(f"/clients/{c.id}/journey/{d}/decline")
    r = admin.post(f"/api/platform/clients/{c.id}/journey/{d}/progress", json={"status": "done"}, headers=bearer())
    assert r.status_code == 409
    # an item belongs to its client
    other = make_client(admin, "Cedar Valley")
    r = admin.post(f"/api/platform/clients/{other.id}/journey/{iid}/progress", json={"status": "done"},
                   headers=bearer())
    assert r.status_code == 404


def test_staff_add_edit_move_and_decline(admin):
    c = make_client(admin)
    r = admin.post(f"/clients/{c.id}/journey", data={"title": "Tabletop exercise", "area": "response",
                                                     "due_on": "2027-01-15", "detail": "Ransomware scenario"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
    item = SessionLocal().query(JourneyItem).filter_by(client_id=c.id).one()
    assert item.status == "planned" and item.source == "staff" and item.decided_by == "admin"
    bad = admin.post(f"/clients/{c.id}/journey", data={"title": "x", "area": "nope"}, follow_redirects=False)
    assert "err=" in bad.headers["location"]
    admin.post(f"/clients/{c.id}/journey/{item.id}/edit",
               data={"title": "Ransomware tabletop", "area": "governance", "due_on": "", "detail": "d", "note": "n"})
    item = SessionLocal().get(JourneyItem, item.id)
    assert item.title == "Ransomware tabletop" and item.area == "governance" and item.due_on is None
    admin.post(f"/clients/{c.id}/journey/{item.id}/status", data={"status": "in_progress"})
    assert SessionLocal().get(JourneyItem, item.id).status == "in_progress"
    r = admin.post(f"/clients/{c.id}/journey/{item.id}/status", data={"status": "proposed"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    # a proposal goes through accept or decline, never a plain move
    p = _propose(admin, c.id).json()["id"]
    r = admin.post(f"/clients/{c.id}/journey/{p}/status", data={"status": "done"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and SessionLocal().get(JourneyItem, p).status == "proposed"
    admin.post(f"/clients/{c.id}/journey/{p}/decline")
    item = SessionLocal().get(JourneyItem, p)
    assert item.status == "declined" and item.decided_by == "admin"
    r = admin.post(f"/clients/{c.id}/journey/{p}/accept", follow_redirects=False)
    assert "err=" in r.headers["location"]
    page = admin.get(f"/clients/{c.id}").text
    assert "Ransomware tabletop" in page and "Enforce MFA for admins" in page


def test_viewer_cannot_change_the_journey(client, admin):
    c = make_client(admin)
    iid = _propose(admin, c.id).json()["id"]
    sign_in_as(client, "board@vendettacd.io", "viewer")
    assert client.get(f"/clients/{c.id}").status_code == 200
    assert client.post(f"/clients/{c.id}/journey/{iid}/accept").status_code == 403
    assert client.post(f"/clients/{c.id}/journey", data={"title": "x", "area": "data"}).status_code == 403
    assert client.post(f"/api/platform/clients/{c.id}/journey", json={"title": "x", "area": "data"}).status_code == 403
    assert SessionLocal().get(JourneyItem, iid).status == "proposed"


def test_journey_item_from_another_client_is_404_on_staff_routes(admin):
    a = make_client(admin, "Alpha")
    b = make_client(admin, "Bravo")
    iid = _propose(admin, a.id).json()["id"]
    assert admin.post(f"/clients/{b.id}/journey/{iid}/accept").status_code == 404
