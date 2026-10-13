"""Case board: playbook seeding, card moves, the update-to-card mapping, escalation
cards, derived workstream status and what the client portal shows."""
from app import auth
from app.config import WORKSTREAMS
from app.db import Case, CaseUpdate, Client, SessionLocal, Task, User, open_case
from app.playbook import PLAYBOOK

from test_hub import DW_PAYLOAD, _bearer


def _case(name="Alpha", **kw):
    db = SessionLocal()
    c = Client(name=name); db.add(c); db.commit()
    return open_case(db, c, "incident", **kw)


def _load(cid):
    db = SessionLocal()
    return db, db.get(Case, cid)


def _cards(case, ws):
    return sorted([t for t in case.tasks if t.workstream == ws], key=lambda t: (t.status, t.position))


def test_case_opens_with_playbook_cards(fresh_db):
    case = _case()
    db, case = _load(case.id)
    for ws in WORKSTREAMS:
        assert sorted(t.title for t in _cards(case, ws)) == sorted(t for t, _ in PLAYBOOK[ws])
    started = [t for t in case.tasks if t.status == "in_progress"]
    assert [t.title for t in started] == [PLAYBOOK[WORKSTREAMS[0]][0][0]]
    assert [w.status for w in case.workstreams] == ["in_progress"] + ["not_started"] * 4
    assert not any(u.kind == "task" for u in case.updates)  # seeding is not timeline noise


def test_moving_cards_logs_and_drives_workstream_status(admin):
    case = _case()
    db, case = _load(case.id)
    ws = "Forensics and Analysis"
    ids = [t.id for t in _cards(case, ws)]
    first = next(t for t in case.tasks if t.id == ids[0])
    r = admin.post(f"/cases/{case.id}/tasks/{ids[0]}/move", data={"status": "in_progress"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("#board")
    db, case = _load(case.id)
    wsrow = next(w for w in case.workstreams if w.name == ws)
    assert wsrow.status == "in_progress"
    assert any(u.kind == "task" and u.task_id == ids[0] and u.note.startswith("Started:") for u in case.updates)
    shared = [u for u in case.updates if u.kind == "status" and u.workstream == ws]
    assert shared and shared[0].internal_only is False and shared[0].note == f"{ws}: in progress."
    for tid in ids:
        admin.post(f"/cases/{case.id}/tasks/{tid}/move", data={"status": "done"})
    db, case = _load(case.id)
    assert next(w for w in case.workstreams if w.name == ws).status == "done"
    assert all(t.completed_at for t in case.tasks if t.workstream == ws)
    # Reopening one card reopens the workstream.
    admin.post(f"/cases/{case.id}/tasks/{first.id}/move", data={"status": "in_progress"})
    db, case = _load(case.id)
    assert next(w for w in case.workstreams if w.name == ws).status == "in_progress"


def test_blocked_card_blocks_an_idle_workstream(admin):
    case = _case()
    db, case = _load(case.id)
    ws = "Notification and Legal"
    tid = _cards(case, ws)[0].id
    admin.post(f"/cases/{case.id}/tasks/{tid}/move", data={"status": "blocked"})
    db, case = _load(case.id)
    assert next(w for w in case.workstreams if w.name == ws).status == "blocked"
    admin.post(f"/cases/{case.id}/tasks/{tid}/move", data={"status": "in_progress"})
    db, case = _load(case.id)
    assert next(u for u in case.updates if u.kind == "task").note.startswith("Resumed:")


def test_update_on_a_card_starts_it_and_can_finish_it(admin):
    case = _case()
    db, case = _load(case.id)
    card = _cards(case, "Forensics and Analysis")[0]
    assert card.status == "todo"
    admin.post(f"/cases/{case.id}/updates", data={"note": "Pulled 90 days of Entra sign-in logs", "target": f"task:{card.id}", "internal_only": "true"})
    db, case = _load(case.id)
    card = db.get(Task, card.id)
    assert card.status == "in_progress"
    entry = next(u for u in case.updates if u.kind == "note")
    assert entry.task_id == card.id and entry.workstream == "Forensics and Analysis"
    assert entry.payload["card_moved"] == {"from": "todo", "to": "in_progress"}
    admin.post(f"/cases/{case.id}/updates", data={"note": "Collection complete", "target": f"task:{card.id}", "move_to": "done", "internal_only": "true"})
    db, case = _load(case.id)
    assert db.get(Task, card.id).status == "done"
    # The card face shows its latest entry.
    page = admin.get(f"/cases/{case.id}").text
    assert "2 updates" in page


def test_internal_update_still_shares_a_client_visible_step(admin):
    case = _case()
    db, case = _load(case.id)
    card = next(t for t in _cards(case, "Scoping and Containment") if t.client_visible and t.status == "todo")
    admin.post(f"/cases/{case.id}/updates", data={"note": "EDR isolation on 14 hosts; suspect insider", "target": f"task:{card.id}", "move_to": "done", "internal_only": "true"})
    db, case = _load(case.id)
    shared = [u for u in case.updates if not u.internal_only and u.kind == "task"]
    assert shared and shared[0].note == f"Completed: {card.title}"
    assert not any("insider" in u.note for u in case.updates if not u.internal_only)


def test_update_can_become_a_card(admin):
    case = _case()
    admin.post(f"/cases/{case.id}/updates", data={"note": "Waiting on firewall logs from the client\nAsked IT on the bridge",
                                                   "target": "ws:Forensics and Analysis", "new_card": "true", "move_to": "blocked", "internal_only": "true"})
    db, case = _load(case.id)
    card = next(t for t in case.tasks if t.source == "update")
    assert card.title == "Waiting on firewall logs from the client" and card.status == "blocked"
    assert next(u for u in case.updates if u.kind == "note").task_id == card.id


def test_update_to_a_card_on_another_case_is_refused(admin):
    a, b = _case("Alpha"), _case("Bravo")
    db, b = _load(b.id)
    other = b.tasks[0]
    r = admin.post(f"/cases/{a.id}/updates", data={"note": "x", "target": f"task:{other.id}"})
    assert r.status_code == 404


def test_escalation_adds_a_review_card_linked_to_the_finding(client):
    r1 = client.post("/api/ir-cases", json=DW_PAYLOAD, headers=_bearer()).json()
    r2 = client.post("/api/ir-cases", json=dict(DW_PAYLOAD, case_ref=r1["case_id"]), headers=_bearer()).json()
    assert r2["linked"]
    db = SessionLocal()
    case = db.query(Case).filter_by(number=r1["case_id"]).one()
    cards = [t for t in case.tasks if t.source == "escalation"]
    assert len(cards) == 2 and all(t.workstream == "Forensics and Analysis" and t.status == "todo" for t in cards)
    assert cards[0].title.startswith("Review: Dark web credential finding")
    findings = [u for u in case.updates if u.kind == "finding"]
    assert {u.task_id for u in findings} == {t.id for t in cards}
    api = client.get("/api/ir-cases", headers=_bearer()).json()[0]
    fa = next(w for w in api["workstreams"] if w["name"] == "Forensics and Analysis")
    assert fa["cards"]["todo"] == len(PLAYBOOK["Forensics and Analysis"]) + 2
    assert api["board"]["total"] == sum(len(v) for v in PLAYBOOK.values()) + 2


def test_drag_move_reorders_changes_lane_and_answers_json(admin):
    case = _case()
    db, case = _load(case.id)
    todo = [t for t in _cards(case, "Recovery and Restoration") if t.status == "todo"]
    last, first = todo[-1], todo[0]
    r = admin.post(f"/cases/{case.id}/tasks/{last.id}/move", data={"status": "todo", "before": first.id},
                   headers={"X-Requested-With": "fetch"})
    assert r.status_code == 200 and r.json() == {"ok": True}
    db, case = _load(case.id)
    col = sorted([t for t in case.tasks if t.workstream == "Recovery and Restoration" and t.status == "todo"], key=lambda t: t.position)
    assert col[0].id == last.id
    assert not any(u.kind == "task" for u in case.updates)  # a reorder is not logged
    admin.post(f"/cases/{case.id}/tasks/{last.id}/move", data={"status": "in_progress", "workstream": "Resilience and Hardening"},
               headers={"X-Requested-With": "fetch"})
    db, case = _load(case.id)
    moved = db.get(Task, last.id)
    assert moved.workstream == "Resilience and Hardening" and moved.status == "in_progress"
    assert next(w for w in case.workstreams if w.name == "Resilience and Hardening").status == "in_progress"
    assert admin.post(f"/cases/{case.id}/tasks/{last.id}/move", data={"status": "nope"}).status_code == 400


def test_add_edit_and_remove_cards(admin):
    case = _case()
    admin.post(f"/cases/{case.id}/tasks", data={"workstream": "Notification and Legal", "title": "  Notify   NCUA within 72 hours ", "client_visible": "true"})
    db, case = _load(case.id)
    card = next(t for t in case.tasks if t.source == "manual")
    assert card.title == "Notify NCUA within 72 hours" and card.client_visible
    admin.post(f"/cases/{case.id}/tasks/{card.id}", data={"title": "Notify NCUA", "owner": "J. Snook", "due_on": "2026-10-15"})
    db, case = _load(case.id)
    card = db.get(Task, card.id)
    assert (card.title, card.owner, str(card.due_on), card.client_visible) == ("Notify NCUA", "J. Snook", "2026-10-15", False)
    admin.post(f"/cases/{case.id}/updates", data={"note": "Drafted notice", "target": f"task:{card.id}"})
    admin.post(f"/cases/{case.id}/tasks/{card.id}/delete")
    db, case = _load(case.id)
    assert db.get(Task, card.id) is None
    kept = next(u for u in case.updates if u.note == "Drafted notice")
    assert kept.task_id is None  # the timeline keeps the entry
    assert admin.post(f"/cases/{case.id}/tasks", data={"workstream": "Nope", "title": "x"}).status_code == 400


def test_workstream_status_follows_board_when_it_has_cards(admin):
    case = _case()
    db, case = _load(case.id)
    w = next(x for x in case.workstreams if x.name == "Recovery and Restoration")
    admin.post(f"/cases/{case.id}/workstreams/{w.id}", data={"status": "done", "owner": "M. Chen", "client_visible_note": "Restores underway"})
    db, case = _load(case.id)
    w = next(x for x in case.workstreams if x.name == "Recovery and Restoration")
    assert w.status == "not_started" and w.owner == "M. Chen" and w.client_visible_note == "Restores underway"


def test_portal_shows_client_steps_only(client):
    case = _case("Mine")
    db = SessionLocal()
    db.add(User(email="it@mine.org", role="client", client_id=case.client_id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@mine.org"))
    page = client.get(f"/portal/cases/{case.id}").text
    visible = [t for ws in PLAYBOOK.values() for t, cv in ws if cv]
    hidden = [t for ws in PLAYBOOK.values() for t, cv in ws if not cv]
    assert all(t in page for t in visible)
    assert not any(t in page for t in hidden)
    assert "steps complete" in page
    db = SessionLocal(); cs = db.get(Case, case.id); cs.privileged = True; db.commit()
    page = client.get(f"/portal/cases/{case.id}").text
    assert "steps complete" in page and visible[0] not in page


def test_case_page_renders_board(admin):
    case = _case()
    page = admin.get(f"/cases/{case.id}").text
    assert 'id="board"' in page and "/static/kanban.js" in page
    assert page.count('class="lane ') == len(WORKSTREAMS)
    assert page.count('draggable="true"') == sum(len(v) for v in PLAYBOOK.values())
