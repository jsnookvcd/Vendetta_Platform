"""Practice boards, engagements, task boards, columns and cards through the web console."""
from conftest import add_user, as_user

from app import service
from app.db import Board, Card, CardEvent, Engagement, SessionLocal


def _open(admin, practice="ir", name="Ransomware response", client="IFB", **extra):
    r = admin.post("/engagements", data={"practice": practice, "name": name, "client": client, **extra},
                   follow_redirects=False)
    assert r.status_code == 303, r.text
    return r.headers["location"].split("/engagements/")[1].split("?")[0]


def test_practice_boards_seeded_with_lifecycle_columns(admin):
    db = SessionLocal()
    ir = service.practice_board(db, "ir")
    ps = service.practice_board(db, "proserv")
    assert [c.name for c in ir.columns][:3] == ["Intake", "Engaged", "Scoping and Containment"]
    assert ps.columns[-1].name == "Closed" and ps.columns[-1].is_done
    assert admin.get("/boards/ir").status_code == 200
    assert admin.get("/boards/proserv").status_code == 200


def test_open_engagement_creates_card_task_board_and_code(admin):
    eid = _open(admin)
    db = SessionLocal()
    e = db.get(Engagement, eid)
    assert e.code.startswith("VCD-IR-") and e.code.endswith("-001") and e.pm_email == "admin"
    card = service.practice_card(db, e)
    assert card.column.name == "Intake" and card.title.startswith(e.code)
    tb = service.engagement_board(db, e)
    assert [c.name for c in tb.columns] == ["Backlog", "To Do", "In Progress", "Blocked", "In Review", "Done"]
    e2 = db.get(Engagement, _open(admin, name="Second"))
    assert e2.code.endswith("-002")
    page = admin.get(f"/engagements/{eid}")
    assert page.status_code == 200 and "Task board" in page.text


def test_tasks_add_move_edit_and_history(admin):
    eid = _open(admin)
    admin.post(f"/engagements/{eid}/tasks", data={"title": "Image DC01", "assignee": "dan@vendettacd.io",
                                                  "labels": "Forensics and Analysis", "priority": "high"})
    db = SessionLocal()
    c = db.query(Card).filter_by(engagement_id=eid, title="Image DC01").one()
    assert c.column.name == "To Do" and c.labels == ["Forensics and Analysis"] and c.priority == "high"
    r = admin.post(f"/api/cards/{c.ref}/move", json={"column": "In Progress", "position": 0})
    assert r.status_code == 200 and r.json()["column"] == "In Progress"
    admin.post(f"/tasks/{c.ref}/edit", data={"title": "Image DC01 and DC02", "due_on": "2026-10-30",
                                             "checklist_add": "hash the image"})
    db = SessionLocal()
    c = db.get(Card, c.id)
    assert c.title == "Image DC01 and DC02" and str(c.due_on) == "2026-10-30" and c.checklist[0]["text"] == "hash the image"
    assert c.column.name == "In Progress"  # saving the form does not move the card
    kinds = [e.kind for e in db.query(CardEvent).filter_by(card_id=c.id)]
    assert "created" in kinds and "moved" in kinds and "updated" in kinds
    assert admin.get(f"/tasks/{c.ref}").status_code == 200


def test_column_add_rename_remove_requires_destination(admin):
    eid = _open(admin)
    db = SessionLocal()
    board = db.query(Board).filter_by(engagement_id=eid).one()
    admin.post(f"/boards/{board.id}/columns", data={"name": "Waiting on Client"})
    admin.post(f"/engagements/{eid}/tasks", data={"title": "Get logs", "column": "Waiting on Client"})
    db = SessionLocal()
    board = db.get(Board, board.id)
    col = next(c for c in board.columns if c.name == "Waiting on Client")
    r = admin.post(f"/boards/{board.id}/columns/{col.id}", data={"action": "remove"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    todo = next(c for c in board.columns if c.name == "To Do")
    admin.post(f"/boards/{board.id}/columns/{col.id}", data={"action": "remove", "move_cards_to": todo.id})
    db = SessionLocal()
    board = db.get(Board, board.id)
    assert "Waiting on Client" not in [c.name for c in board.columns]
    assert db.query(Card).filter_by(title="Get logs").one().column.name == "To Do"
    admin.post(f"/boards/{board.id}/columns/{todo.id}", data={"action": "save", "name": "Ready", "wip_limit": "1"})
    db = SessionLocal()
    assert db.get(Board, board.id).columns[1].name == "Ready"


def test_wip_limit_blocks_a_move(admin):
    eid = _open(admin)
    for t in ("a", "b"):
        admin.post(f"/engagements/{eid}/tasks", data={"title": t})
    db = SessionLocal()
    e = db.get(Engagement, eid)
    b = service.engagement_board(db, e)
    service.update_column(db, "admin", b, "In Progress", wip_limit=1)
    db.commit()
    a, bb = db.query(Card).filter_by(engagement_id=eid, title="a").one(), db.query(Card).filter_by(title="b").one()
    assert admin.post(f"/api/cards/{a.ref}/move", json={"column": "In Progress"}).status_code == 200
    r = admin.post(f"/api/cards/{bb.ref}/move", json={"column": "In Progress"})
    assert r.status_code == 409 and "WIP limit" in r.json()["detail"]


def test_archive_restore_and_delete(admin):
    eid = _open(admin)
    admin.post(f"/engagements/{eid}/tasks", data={"title": "temp"})
    db = SessionLocal()
    c = db.query(Card).filter_by(title="temp").one()
    admin.post(f"/tasks/{c.ref}/remove", data={"mode": "archive"})
    assert SessionLocal().get(Card, c.id).archived
    admin.post(f"/tasks/{c.ref}/remove", data={"mode": "restore"})
    assert not SessionLocal().get(Card, c.id).archived
    admin.post(f"/tasks/{c.ref}/remove", data={"mode": "delete"})
    db = SessionLocal()
    assert db.get(Card, c.id) is None
    assert db.query(CardEvent).filter_by(card_id=c.id, kind="deleted").count() == 1


def test_closing_moves_practice_card_to_closed(admin):
    eid = _open(admin, practice="proserv", name="Tabletop")
    r = admin.post(f"/engagements/{eid}/edit", data={"status": "closed"}, follow_redirects=False)
    assert "closeout" in r.headers["location"] and SessionLocal().get(Engagement, eid).status == "active"
    admin.post(f"/engagements/{eid}/edit", data={"status": "closed", "force": "true"})
    db = SessionLocal()
    e = db.get(Engagement, eid)
    assert e.status == "closed" and service.practice_card(db, e).column.name == "Closed"


def test_viewer_reads_but_cannot_change(client):
    add_user("viewer@vendettacd.io", "viewer")
    add_user("pm@vendettacd.io", "analyst")
    as_user(client, "pm@vendettacd.io")
    eid = _open(client)
    as_user(client, "viewer@vendettacd.io")
    assert client.get(f"/engagements/{eid}").status_code == 200
    r = client.post(f"/engagements/{eid}/tasks", data={"title": "nope"}, follow_redirects=False)
    assert r.status_code == 403
    assert SessionLocal().query(Card).filter_by(title="nope").count() == 0


def test_unknown_and_inactive_users_are_refused(client):
    add_user("gone@vendettacd.io", "analyst", active=False)
    as_user(client, "gone@vendettacd.io")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login")


def test_service_api_and_idempotent_create(client):
    from app import auth
    h = {"Authorization": f"Bearer {auth.api_token()}"}
    body = {"practice": "ir", "name": "Hub case", "code": "VCD-IR-2026-445", "platform_ref": "case-9"}
    r1 = client.post("/api/engagements", json=body, headers=h)
    r2 = client.post("/api/engagements", json=body, headers=h)
    assert r1.status_code == 201 and r2.status_code == 200 and r2.json()["code"] == "VCD-IR-2026-445"
    assert client.get("/api/engagements", headers=h).json()["engagements"][0]["platform_ref"] == "case-9"
    assert client.get("/api/boards/ir", headers=h).json()["columns"][0]["count"] == 1
    assert client.get("/api/engagements").status_code == 401
    assert client.get("/api/module").json()["mcp"] == "/mcp"
