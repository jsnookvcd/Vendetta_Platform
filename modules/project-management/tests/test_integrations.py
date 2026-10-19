"""Harvest time entries and the SharePoint mirror, against in-memory fakes."""
import io
import json

from conftest import Mcp, add_user, connect_claude

from app import service, sharepoint
from app.db import MeetingNote, SessionLocal, TimeLog


def _eng(m, project="501"):
    return m.ok("create_engagement", practice="ir", name="IFB malware", client="IFB", harvest_project_id=project,
                budget_hours=100)


def test_log_time_as_the_pm_and_burn(client, fake_harvest):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    e = _eng(m)
    assert e["harvest_project"] == "IFB Incident Response"
    t = m.ok("create_task", engagement=e["code"], title="Detonate sample")
    entry = m.ok("log_time", engagement=e["code"], hours=2.5, task="forensic", date="2026-10-19", card=str(t["ref"]))
    assert entry["task"] == "Forensic Analysis" and entry["hours"] == 2.5
    sent = json.loads(next(r for r in fake_harvest.requests if r.method == "POST").content)
    assert sent["user_id"] == 11 and sent["project_id"] == 501 and sent["task_id"] == 901
    assert sent["notes"] == "Detonate sample"
    hist = m.ok("get_task", task=str(t["ref"]))["history"]
    assert any(h["kind"] == "time" for h in hist)
    burn = m.ok("engagement_burn", engagement=e["code"])
    assert burn["total_hours"] == 2.5 and burn["remaining_hours"] == 97.5
    mine = m.ok("list_time_entries", start="2026-10-01")
    assert mine["total_hours"] == 2.5
    assert SessionLocal().query(TimeLog).filter_by(action="created").count() == 1


def test_ambiguous_task_lists_choices(client, fake_harvest):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    e = _eng(m)
    r = m.call("log_time", engagement=e["code"], hours=1, task="admin")
    assert r["isError"] and "Forensic Analysis" in r["content"][0]["text"]
    unlinked = m.ok("create_engagement", practice="proserv", name="No harvest")
    r = m.call("log_time", engagement=unlinked["code"], hours=1, task="x")
    assert r["isError"] and "not linked to a Harvest project" in r["content"][0]["text"]
    tasks = m.ok("list_harvest_tasks", engagement=e["code"])["tasks"]
    assert {t["name"] for t in tasks} == {"Forensic Analysis", "Project Management"}


def test_only_admin_logs_or_changes_for_others(client, fake_harvest):
    add_user("pm@vendettacd.io")
    add_user("dan@vendettacd.io")
    pm = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    e = _eng(pm)
    r = pm.call("log_time", engagement=e["code"], hours=1, task="Project Management", user="dan@vendettacd.io")
    assert r["isError"] and "admin" in r["content"][0]["text"]
    dan = Mcp(client, connect_claude(client, "dan@vendettacd.io")["access_token"])
    entry = dan.ok("log_time", engagement=e["code"], hours=3, task="Forensic Analysis")
    r = pm.call("delete_time_entry", entry_id=entry["id"])
    assert r["isError"] and "only your own" in r["content"][0]["text"]
    upd = dan.ok("update_time_entry", entry_id=entry["id"], hours=3.5, notes="memory analysis")
    assert upd["hours"] == 3.5
    dan.ok("delete_time_entry", entry_id=entry["id"])
    assert not fake_harvest.entries


def test_admin_logs_for_someone_else_from_the_web(admin, fake_harvest):
    admin.post("/engagements", data={"practice": "ir", "name": "IFB", "harvest_project_id": "501"})
    db = SessionLocal()
    code = service.list_engagements(db)[0].code
    r = admin.post("/time", data={"engagement": code, "hours": "1.5", "task": "902", "spent_date": "2026-10-18"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
    entry = next(iter(fake_harvest.entries.values()))
    assert entry["user_id"] == 13 and entry["hours"] == 1.5 and entry["spent_date"] == "2026-10-18"


def test_note_mirrors_to_sharepoint_as_docx(client, fake_graph):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    e = m.ok("create_engagement", practice="ir", name="Rize second IR", code="VCD-IR-2026-500")
    n = m.ok("log_meeting_notes", engagement=e["code"], title="Daily sync: day 2", held_at="2026-10-19T14:00:00Z",
             body="## Status\n- EDR deployed\n1. next: memory", decisions="Rebuild DC",
             action_items=[{"text": "Order replacement hardware"}])
    assert n["sharepoint"]["status"] == "mirrored" and n["sharepoint"]["url"].startswith("https://sp.example/")
    path = fake_graph.puts[0]
    assert "Engagements/VCD-IR-2026-500/Meeting Notes/2026-10-19 Daily sync day 2.docx" in path.replace("%20", " ")
    from docx import Document
    doc = Document(io.BytesIO(next(iter(fake_graph.files.values()))))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "EDR deployed" in text and "Rebuild DC" in text and "Order replacement hardware" in text
    m.ok("update_meeting_note", note_id=n["id"], append="Late add")
    assert len(fake_graph.files) == 1  # overwritten by item id, not duplicated
    assert "/items/item-1/content" in fake_graph.puts[-1]


def test_case_site_wins_and_failures_are_kept_and_retried(client, fake_graph):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    e = m.ok("create_engagement", practice="ir", name="Case site",
             sharepoint_site_url="https://vendettacd.sharepoint.com/sites/IR-2026-501")
    db = SessionLocal()
    eng = service.find_engagement(db, e["code"])
    assert sharepoint.target(eng) == ("https://vendettacd.sharepoint.com/sites/IR-2026-501", "Meeting Notes")
    fake_graph.fail = True
    n = m.ok("log_meeting_notes", engagement=e["code"], title="Call")
    assert n["sharepoint"]["status"] == "failed" and "may not write" in n["sharepoint"]["error"]
    assert SessionLocal().get(MeetingNote, n["id"]).body == ""  # the note itself was kept
    fake_graph.fail = False
    assert m.ok("retry_sharepoint_mirror", note_id=n["id"])["sharepoint"]["status"] == "mirrored"
