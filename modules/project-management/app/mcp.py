"""Remote MCP server at /mcp (Streamable HTTP transport, JSON responses).

A PM adds https://pm.<domain>/mcp to Claude as a custom connector, signs in once
(see oauth.py), and then works the boards, tasks, meeting notes and Harvest time by
talking to Claude. Every tool calls the same service layer the web board uses, as
the signed-in PM, with that PM's current role: a viewer gets the read tools only.

The server is stateless: each POST carries one JSON-RPC message (or a batch) and
gets a JSON reply, which the Streamable HTTP transport permits in place of an SSE
stream. Notifications get 202. There is no server-initiated stream, so GET is 405.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from . import alerts as alerts_mod
from . import billing, capacity, changes, harvest, integrations, metrics, oauth, service, templates_lib
from . import milestones as milestones_mod
from .auth import Identity
from .config import IR_WORKSTREAMS, PRACTICE_NAMES
from .db import AuditLog, SessionLocal
from .service import ServiceError

log = logging.getLogger(__name__)
router = APIRouter()

SERVER_NAME = "vendetta-project-management"
SERVER_VERSION = "1.0.0"
SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
INSTRUCTIONS = (
    "Vendetta Project Management for the Incident Response (ir) and Professional Services (proserv) "
    "practices. Engagements are identified by code (VCD-IR-2026-445) or a unique part of the name. Each "
    "practice has a Kanban board whose columns are engagement phases; each engagement has its own task "
    "board. Tasks are referred to by number (#214). 'me' means the signed-in PM wherever a person is "
    "asked for. Meeting notes are saved here and mirrored to SharePoint. Time goes to Harvest: an "
    "engagement must be linked to a Harvest project, and the Harvest task is named per entry (use "
    "list_harvest_tasks when unsure). Confirm hours, date and task with the PM before logging time "
    "for someone else or deleting anything. Open new engagements from a template when one fits "
    "(list_templates). Anything that changes sold hours or the end date goes through request_change, "
    "never a direct budget edit. Invoices are only ever drafted; confirm the period with the PM first."
)


# ---------------------------------------------------------------- tool registry
class Tool:
    def __init__(self, name: str, description: str, schema: dict, fn: Callable, write: bool,
                 destructive: bool = False):
        self.name, self.description, self.schema, self.fn = name, description, schema, fn
        self.write, self.destructive = write, destructive

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description, "inputSchema": self.schema,
                "annotations": {"readOnlyHint": not self.write, "destructiveHint": self.destructive,
                                "idempotentHint": not self.write, "openWorldHint": self.name in _OPEN_WORLD}}


TOOLS: dict[str, Tool] = {}
_OPEN_WORLD = {"log_time", "update_time_entry", "delete_time_entry", "list_time_entries", "list_harvest_projects",
               "list_harvest_tasks", "engagement_burn", "log_meeting_notes", "update_meeting_note",
               "retry_sharepoint_mirror", "draft_invoice", "uninvoiced_time", "manage_milestone",
               "apply_template", "team_capacity", "portfolio_metrics"}


def S(**props) -> dict:
    """A JSON schema object. Keys ending in '!' are required."""
    req = [k.rstrip("!") for k in props if k.endswith("!")]
    return {"type": "object", "properties": {k.rstrip("!"): v for k, v in props.items()}, "required": req,
            "additionalProperties": False}


def tool(name: str, description: str, schema: dict, *, write: bool = False, destructive: bool = False):
    def deco(fn):
        TOOLS[name] = Tool(name, description, schema, fn, write, destructive)
        return fn
    return deco


STR = {"type": "string"}
INT = {"type": "integer"}
NUM = {"type": "number"}
BOOL = {"type": "boolean"}
DATE = {"type": "string", "description": "YYYY-MM-DD, or today / yesterday / tomorrow"}
ENG = {"type": "string", "description": "Engagement code (VCD-IR-2026-445) or a unique part of its name or client"}
TASK = {"type": "string", "description": "Task number, like 214 or #214"}
WHO = {"type": "string", "description": "Staff email, or 'me'"}
PRACTICE = {"type": "string", "enum": ["ir", "proserv"]}
LABELS = {"type": "array", "items": STR}


def _who(ident: Identity, v: str | None) -> str | None:
    if v is None or v == "":
        return None
    return ident.email if v.strip().lower() in ("me", "myself", "self") else v.strip().lower()


def _cards(rows) -> list[dict]:
    return [service.card_dict(c, brief=True) for c in rows]


# ---------------------------------------------------------------- read tools
@tool("whoami", "Who you are signed in as, your role, and which integrations (Harvest, SharePoint) are live.", S())
def t_whoami(db, ident):
    st = integrations.status()
    return {"email": ident.email, "role": ident.role, "read_only": ident.is_viewer,
            "practices": PRACTICE_NAMES, "harvest_connected": st["harvest"],
            "sharepoint_connected": st["graph"] and st["sharepoint_site"]}


@tool("my_work", "Your work at a glance: engagements you run, your open tasks (overdue first), and your "
      "Harvest hours this week.", S(include_time=BOOL))
def t_my_work(db, ident, include_time=True):
    engs = service.list_engagements(db, pm=ident.email)
    tasks = service.list_tasks(db, assignee=ident.email)
    out = {"engagements": [service.engagement_dict(db, e) for e in engs], "open_tasks": _cards(tasks),
           "overdue": sum(1 for t in tasks if t.due_on and t.due_on < dt.date.today())}
    if include_time and harvest.configured():
        start = dt.date.today() - dt.timedelta(days=dt.date.today().weekday())
        try:
            entries = harvest.list_entries(user_email=ident.email, start=start)
            out["hours_this_week"] = round(sum(float(e["hours"] or 0) for e in entries), 2)
        except harvest.HarvestError as e:
            out["hours_this_week"] = f"unavailable: {e}"
    return out


@tool("list_engagements", "List engagements. Defaults to open ones across both practices.",
      S(practice=PRACTICE, status={"type": "string", "enum": ["open", "active", "on_hold", "closed", "all"]},
        pm=WHO, query=STR))
def t_list_engagements(db, ident, practice=None, status="open", pm=None, query=None):
    rows = service.list_engagements(db, practice=practice, status=status, pm=_who(ident, pm), query=query)
    return {"count": len(rows), "engagements": [service.engagement_dict(db, e) for e in rows]}


@tool("get_engagement", "One engagement in detail: phase on the practice board, task counts by column, "
      "Harvest link, SharePoint folder and recent meeting notes.", S(**{"engagement!": ENG}))
def t_get_engagement(db, ident, engagement):
    return service.engagement_dict(db, service.find_engagement(db, engagement), detail=True)


@tool("get_board", "A Kanban board with its columns and cards. Use 'ir' or 'proserv' for a practice board "
      "(cards are engagements, columns are phases) or an engagement code for its task board.",
      S(**{"board!": {"type": "string", "description": "ir, proserv, or an engagement code"}},
        assignee=WHO, label=STR, include_done=BOOL))
def t_get_board(db, ident, board, assignee=None, label=None, include_done=False):
    b = service.find_board(db, board)
    return service.board_dict(db, b, include_done=include_done, assignee=_who(ident, assignee), label=label)


@tool("list_tasks", "Find tasks across engagements. Open tasks only unless include_done or a column is given.",
      S(engagement=ENG, assignee=WHO, column=STR, label=STR, overdue=BOOL,
        due_within_days=INT, include_done=BOOL, query=STR, practice=PRACTICE))
def t_list_tasks(db, ident, engagement=None, assignee=None, column=None, label=None, overdue=False,
                 due_within_days=None, include_done=False, query=None, practice=None):
    eng = service.find_engagement(db, engagement) if engagement else None
    rows = service.list_tasks(db, engagement=eng, assignee=_who(ident, assignee), column=column, label=label,
                              overdue=overdue, due_within_days=due_within_days, include_done=include_done,
                              query=query, practice=practice)
    return {"count": len(rows), "tasks": _cards(rows)}


@tool("get_task", "One task or card with its full detail, checklist and history (moves, edits, comments, "
      "time logged).", S(**{"task!": TASK}))
def t_get_task(db, ident, task):
    c = service.find_card(db, task)
    return {**service.card_dict(c), "history": service.card_history(db, c.id)}


@tool("list_meeting_notes", "List or search meeting notes, newest first.",
      S(engagement=ENG, query=STR, since=DATE, limit=INT))
def t_list_notes(db, ident, engagement=None, query=None, since=None, limit=25):
    eng = service.find_engagement(db, engagement) if engagement else None
    rows = service.list_notes(db, engagement=eng, query=query, since=since, limit=min(int(limit or 25), 100))
    return {"count": len(rows), "notes": [service.note_dict(n, full=False) for n in rows]}


@tool("get_meeting_note", "The full text of a meeting note.", S(**{"note_id!": STR}))
def t_get_note(db, ident, note_id):
    return service.note_dict(service.find_note(db, note_id))


@tool("list_harvest_projects", "Active Harvest projects, optionally filtered by name, code or client. Use the "
      "id to link an engagement.", S(query=STR))
def t_harvest_projects(db, ident, query=""):
    rows = harvest.list_projects(query or "")
    return {"count": len(rows), "projects": rows[:100]}


@tool("list_harvest_tasks", "The Harvest tasks you can log time to on an engagement's project (or a Harvest "
      "project id).", S(engagement=ENG, project=STR))
def t_harvest_tasks(db, ident, engagement=None, project=None):
    pid, _eng = service._project_for(db, engagement, project)
    return {"project_id": pid, "tasks": harvest.list_tasks(pid)}


@tool("list_time_entries", "Harvest time entries. Defaults to your own for the last 7 days. user='all' with an "
      "engagement shows the whole team.", S(engagement=ENG, project=STR, user=WHO, start=DATE, end=DATE))
def t_list_time(db, ident, engagement=None, project=None, user="me", start=None, end=None):
    pid = service._project_for(db, engagement, project)[0] if (engagement or project) else None
    who = None if (user or "").lower() == "all" else (_who(ident, user) or ident.email)
    s = service.parse_date(start) or (dt.date.today() - dt.timedelta(days=7))
    rows = harvest.list_entries(user_email=who, project_id=pid, start=s, end=service.parse_date(end))
    return {"count": len(rows), "total_hours": round(sum(float(r["hours"] or 0) for r in rows), 2),
            "entries": rows}


@tool("engagement_burn", "Hours logged in Harvest against an engagement, by person and task, against its "
      "budget.", S(**{"engagement!": ENG}))
def t_burn(db, ident, engagement):
    return service.burn(db, service.find_engagement(db, engagement))


# ---------------------------------------------------------------- engagements
@tool("create_engagement", "Open a new IR or Professional Services engagement. It gets a card on the practice "
      "board (in the first phase unless phase is given) and its own task board. The code is generated "
      "(VCD-IR-2026-001 / VCD-PS-2026-001) unless you pass one.",
      S(**{"practice!": PRACTICE, "name!": STR}, client=STR, code=STR, pm=WHO, lead=WHO,
        template={"type": "string", "description": "Template key (bec, ransomware, malware-analysis, ir-general, "
                  "tabletop, vciso-onboarding, pentest, pre-ransomware, or your own); lays down its tasks, "
                  "milestones, budget and closeout"},
        description=STR, budget_hours=NUM, starts_on=DATE, ends_on=DATE, harvest_project_id=STR,
        sharepoint_site_url=STR, platform_ref={"type": "string", "description": "IR hub case number "
                                               "(VCD-IR-2026-781) or OSP engagement id; milestones show to the client "
                                               "there"},
        phase=STR), write=True)
def t_create_engagement(db, ident, practice, name, pm=None, lead=None, phase=None, **f):
    e = service.create_engagement(db, ident.email, practice=practice, name=name, pm_email=_who(ident, pm),
                                  lead_email=_who(ident, lead), column=phase, **f)
    if e.platform_ref:
        milestones_mod.publish(db, e)
    out = service.engagement_dict(db, e, detail=True)
    if e.practice == "ir":
        out["hint"] = "IR tasks can carry a workstream label: " + ", ".join(IR_WORKSTREAMS)
    return out


@tool("update_engagement", "Change an engagement's details, link its Harvest project or SharePoint site, or set "
      "its status (active, on_hold, closed; closing moves its card to the done column).",
      S(**{"engagement!": ENG}, name=STR, client=STR, pm=WHO, lead=WHO, description=STR,
        budget_hours={"type": "number", "description": "Prefer request_change for anything sold: it keeps the "
                      "baseline and the reason"},
        starts_on=DATE, ends_on=DATE, harvest_project_id=STR, sharepoint_site_url=STR, sharepoint_folder=STR,
        platform_ref=STR, status={"type": "string", "enum": ["active", "on_hold", "closed"]},
        force={"type": "boolean", "description": "Close even with closeout items open"}), write=True)
def t_update_engagement(db, ident, engagement, pm=None, lead=None, **f):
    e = service.find_engagement(db, engagement)
    if pm is not None:
        f["pm_email"] = _who(ident, pm)
    if lead is not None:
        f["lead_email"] = _who(ident, lead) or ""
    ref_before = e.platform_ref
    service.update_engagement(db, ident.email, e, **f)
    if e.platform_ref and e.platform_ref != ref_before:
        milestones_mod.publish(db, e)
    return service.engagement_dict(db, e, detail=True)


@tool("move_engagement", "Move an engagement to another phase (column) on its practice board.",
      S(**{"engagement!": ENG, "phase!": STR}, position=INT), write=True)
def t_move_engagement(db, ident, engagement, phase, position=None):
    e = service.find_engagement(db, engagement)
    card = service.practice_card(db, e)
    if card is None:
        raise ServiceError(f"{e.code} has no card on its practice board")
    service.move_card(db, ident.email, card, phase, position)
    return service.engagement_dict(db, e)


# ---------------------------------------------------------------- tasks
_TASK_FIELDS = dict(description=STR, assignee=WHO, due_on=DATE,
                    priority={"type": "string", "enum": ["low", "normal", "high", "urgent"]},
                    labels=LABELS, column=STR, estimate_hours=NUM, checklist=LABELS)


@tool("create_task", "Add a task to an engagement's task board (To Do unless a column is given). For IR, a "
      "workstream name works well as a label.", S(**{"engagement!": ENG, "title!": STR}, **_TASK_FIELDS),
      write=True)
def t_create_task(db, ident, engagement, title, assignee=None, **f):
    e = service.find_engagement(db, engagement)
    c = service.create_task(db, ident.email, e, title=title, assignee=_who(ident, assignee), **f)
    return service.card_dict(c)


@tool("create_tasks", "Add several tasks to one engagement at once (for example from a call or a plan).",
      S(**{"engagement!": ENG, "tasks!": {"type": "array", "items": S(**{"title!": STR}, **_TASK_FIELDS)}}),
      write=True)
def t_create_tasks(db, ident, engagement, tasks):
    e = service.find_engagement(db, engagement)
    made = []
    for t in tasks:
        t = dict(t)
        t["assignee"] = _who(ident, t.get("assignee"))
        made.append(service.create_task(db, ident.email, e, **t))
    return {"created": len(made), "tasks": _cards(made)}


@tool("update_task", "Change a task: title, description, assignee, due date ('none' clears it), priority, "
      "labels, estimate, checklist (add items, or check items off by number), or its column.",
      S(**{"task!": TASK}, title=STR, description=STR, assignee=WHO, due_on=DATE,
        priority={"type": "string", "enum": ["low", "normal", "high", "urgent"]}, labels=LABELS,
        add_labels=LABELS, remove_labels=LABELS, estimate_hours=NUM, checklist_add=LABELS,
        checklist_check={"type": "array", "items": INT, "description": "1-based item numbers to mark done"},
        column=STR), write=True)
def t_update_task(db, ident, task, assignee=None, **f):
    c = service.find_card(db, task)
    if assignee is not None:
        f["assignee"] = _who(ident, assignee) or ""
    service.update_card(db, ident.email, c, **f)
    return service.card_dict(c)


@tool("move_task", "Move a task (or any card) to another column, optionally to a position (0 is the top).",
      S(**{"task!": TASK, "column!": STR}, position=INT), write=True)
def t_move_task(db, ident, task, column, position=None):
    c = service.move_card(db, ident.email, service.find_card(db, task), column, position)
    return service.card_dict(c, brief=True)


@tool("comment_on_task", "Add a comment to a task's history.", S(**{"task!": TASK, "text!": STR}), write=True)
def t_comment(db, ident, task, text):
    c = service.find_card(db, task)
    service.comment(db, ident.email, c, text)
    return {"ok": True, "task": c.ref}


@tool("remove_task", "Remove a task. 'archive' (the default) hides it and keeps it restorable; 'delete' removes "
      "it for good, keeping only its history line.",
      S(**{"task!": TASK}, mode={"type": "string", "enum": ["archive", "delete"]}), write=True, destructive=True)
def t_remove_task(db, ident, task, mode="archive"):
    c = service.find_card(db, task)
    if mode == "delete":
        return service.delete_card(db, ident.email, c)
    service.archive_card(db, ident.email, c, True)
    return {"archived": c.ref, "title": c.title}


@tool("restore_task", "Bring an archived task back onto its board.", S(**{"task!": TASK}), write=True)
def t_restore_task(db, ident, task):
    return service.card_dict(service.archive_card(db, ident.email, service.find_card(db, task), False), brief=True)


@tool("manage_board_column", "Add, rename, reorder, change, or remove a column on a board. Removing a column "
      "that holds cards needs move_cards_to.",
      S(**{"board!": {"type": "string", "description": "ir, proserv, or an engagement code"},
           "action!": {"type": "string", "enum": ["add", "rename", "move", "update", "remove"]}},
        column={"type": "string", "description": "The existing column (not needed for add)"},
        name={"type": "string", "description": "New column name (add, rename)"},
        position={"type": "integer", "description": "0-based position (add, move)"},
        wip_limit={"type": "integer", "description": "Max cards; 0 clears"}, is_done=BOOL, move_cards_to=STR),
      write=True, destructive=True)
def t_column(db, ident, board, action, column=None, name=None, position=None, wip_limit=None, is_done=None,
             move_cards_to=None):
    b = service.find_board(db, board)
    if action == "add":
        service.add_column(db, ident.email, b, name or column or "", position, wip_limit or None, is_done)
    elif action == "remove":
        res = service.delete_column(db, ident.email, b, column or "", move_cards_to)
        return {**res, "board": service.board_dict(db, b, include_done=False)}
    else:
        if not column:
            raise ServiceError("Name the column to change")
        service.update_column(db, ident.email, b, column, name=name if action in ("rename", "update") else None,
                              position=position if action in ("move", "update") else None,
                              wip_limit=wip_limit if wip_limit is not None else "unchanged", is_done=is_done)
    return {"board": b.name, "columns": [{"name": c.name, "position": c.position, "wip_limit": c.wip_limit,
                                          "is_done": c.is_done} for c in sorted(b.columns, key=lambda c: c.position)]}


# ---------------------------------------------------------------- meeting notes
ACTION = S(**{"text!": STR}, assignee=WHO, due_on=DATE)


@tool("log_meeting_notes", "Record a meeting on an engagement. The note is saved here and written to the "
      "engagement's SharePoint folder as a Word document. Action items become tasks on the engagement's "
      "board unless create_tasks is false.",
      S(**{"engagement!": ENG, "title!": STR}, held_at={"type": "string", "description": "ISO date or datetime; "
        "defaults to now"}, attendees=STR, body={"type": "string", "description": "The notes, in markdown"},
        decisions=STR, action_items={"type": "array", "items": ACTION}, create_tasks=BOOL), write=True)
def t_log_note(db, ident, engagement, title, action_items=None, create_tasks=True, **f):
    e = service.find_engagement(db, engagement)
    items = [{**a, "assignee": _who(ident, a.get("assignee")) or ""} for a in (action_items or [])]
    n = service.create_note(db, ident.email, e, title=title, action_items=items, create_tasks=create_tasks, **f)
    return service.note_dict(n)


@tool("update_meeting_note", "Edit a meeting note or append to it; the SharePoint copy is rewritten.",
      S(**{"note_id!": STR}, title=STR, attendees=STR, body=STR, append=STR, decisions=STR, held_at=STR,
        action_items={"type": "array", "items": ACTION}), write=True)
def t_update_note(db, ident, note_id, action_items=None, **f):
    n = service.find_note(db, note_id)
    if action_items:
        f["action_items"] = [{**a, "assignee": _who(ident, a.get("assignee")) or ""} for a in action_items]
    service.update_note(db, ident.email, n, **f)
    return service.note_dict(n)


@tool("retry_sharepoint_mirror", "Try again to write a meeting note to SharePoint after a failure.",
      S(**{"note_id!": STR}), write=True)
def t_retry_mirror(db, ident, note_id):
    from . import sharepoint
    n = service.find_note(db, note_id)
    sharepoint.mirror(n, n.engagement)
    return service.note_dict(n, full=False)


# ---------------------------------------------------------------- time
@tool("log_time", "Log hours to Harvest. Give the engagement (its linked Harvest project is used) or a Harvest "
      "project, and the Harvest task name. Logs for you unless an admin names someone else. Optionally tie it to "
      "a board task, which records it in that task's history.",
      S(**{"hours!": NUM, "task!": {"type": "string", "description": "Harvest task name or id"}},
        engagement=ENG, project={"type": "string", "description": "Harvest project id or name, if not using an "
                                 "engagement"}, date=DATE, notes=STR, user=WHO, card=TASK), write=True)
def t_log_time(db, ident, hours, task, engagement=None, project=None, date=None, notes="", user=None, card=None):
    return service.log_time(db, ident.email, ident.role, hours=hours, task=task, spent_date=date,
                            engagement=engagement, project=project, notes=notes or "",
                            user_email=_who(ident, user), card_ref=card)


@tool("update_time_entry", "Change one of your Harvest entries (admins: anyone's).",
      S(**{"entry_id!": STR}, hours=NUM, notes=STR, date=DATE, task=STR), write=True)
def t_update_time(db, ident, entry_id, hours=None, notes=None, date=None, task=None):
    return service.update_time(db, ident.email, ident.role, entry_id, hours=hours, notes=notes, spent_date=date,
                               task=task)


@tool("delete_time_entry", "Delete one of your Harvest entries (admins: anyone's). Locked entries cannot be "
      "deleted.", S(**{"entry_id!": STR}), write=True, destructive=True)
def t_delete_time(db, ident, entry_id):
    return service.delete_time(db, ident.email, ident.role, entry_id)


# ---------------------------------------------------------------- templates
@tool("list_templates", "The engagement templates: the standard task sets, milestones and budgets per engagement "
      "type.", S(practice=PRACTICE))
def t_list_templates(db, ident, practice=None):
    from sqlalchemy import select
    from .db import Template
    q = select(Template).where(Template.active.is_(True))
    if practice:
        q = q.where(Template.practice == practice)
    return {"templates": [templates_lib.template_dict(t, full=False)
                          for t in db.execute(q.order_by(Template.practice, Template.name)).scalars()]}


@tool("get_template", "One template in full: tasks (owner by role pm/lead, due offset in days), milestones, "
      "budget, target days per phase, closeout.", S(**{"template!": STR}))
def t_get_template(db, ident, template):
    return templates_lib.template_dict(templates_lib.find(db, template))


@tool("save_template", "Create or change a template by key, or capture a finished engagement's board as a new "
      "one (from_engagement). Tasks: [{title, owner: pm|lead|email, offset_days, estimate_hours, labels, "
      "priority, checklist, column}]. Milestones: [{title, offset_days, workstream, client_visible}].",
      S(**{"key!": STR}, name=STR, practice=PRACTICE, description=STR, budget_hours=NUM, duration_days=INT,
        tasks={"type": "array", "items": {"type": "object"}}, milestones={"type": "array", "items": {"type": "object"}},
        phase_days={"type": "object", "description": "Target days per practice-board phase"},
        closeout=LABELS, active=BOOL, from_engagement=ENG), write=True)
def t_save_template(db, ident, key, from_engagement=None, **f):
    if from_engagement:
        e = service.find_engagement(db, from_engagement)
        t = templates_lib.from_engagement(db, ident.email, e, key=key, name=f.get("name") or f"{e.name} template")
    else:
        t = templates_lib.save(db, ident.email, key=key, **f)
    return templates_lib.template_dict(t)


@tool("apply_template", "Lay a template onto an existing engagement: its tasks (dated from the start), "
      "milestones, closeout, and any budget or end date the engagement lacks.",
      S(**{"engagement!": ENG, "template!": STR}, start=DATE), write=True)
def t_apply_template(db, ident, engagement, template, start=None):
    e = service.find_engagement(db, engagement)
    res = templates_lib.apply(db, ident.email, e, templates_lib.find(db, template), start=service.parse_date(start))
    if e.platform_ref:
        res["publish"] = milestones_mod.publish(db, e)
    return res


# ---------------------------------------------------------------- milestones
@tool("manage_milestone", "Add, update (status planned/in_progress/at_risk/done, title, due date, workstream, "
      "client visibility) or remove a milestone, or publish. Client-visible milestones are pushed to the client's "
      "portal (IR hub case or OSP engagement) after every change.",
      S(**{"engagement!": ENG, "action!": {"type": "string", "enum": ["add", "update", "remove", "publish"]}},
        milestone={"type": "string", "description": "Existing milestone title or id (update, remove)"},
        title=STR, status={"type": "string", "enum": ["planned", "in_progress", "at_risk", "done"]},
        due_on=DATE, workstream=STR, client_visible=BOOL), write=True)
def t_milestone(db, ident, engagement, action, milestone=None, title=None, status=None, due_on=None,
                workstream=None, client_visible=None):
    e = service.find_engagement(db, engagement)
    if action == "add":
        m = milestones_mod.add(db, ident.email, e, title=title or "", due_on=due_on, workstream=workstream,
                               client_visible=True if client_visible is None else client_visible)
        if status:
            milestones_mod.update(db, ident.email, m, status=status)
    elif action == "update":
        milestones_mod.update(db, ident.email, milestones_mod.find(db, e, milestone or ""), title=title,
                              status=status, due_on=due_on, workstream=workstream, client_visible=client_visible)
    elif action == "remove":
        milestones_mod.remove(db, ident.email, milestones_mod.find(db, e, milestone or ""))
    pub = milestones_mod.publish(db, e)
    return {"engagement": e.code, "milestones": [milestones_mod.milestone_dict(m) for m in milestones_mod.list_for(db, e)],
            "client_portal": pub}


# ---------------------------------------------------------------- capacity
@tool("team_capacity", "Who is loaded and who is free, week by week, from task estimates and due dates against "
      "each person's weekly capacity, with this week's Harvest hours. Give hours (and practice) to ask whether "
      "the team can take on a new engagement of that size.",
      S(weeks=INT, practice=PRACTICE, hours={"type": "number", "description": "Size of a prospective engagement"}))
def t_capacity(db, ident, weeks=4, practice=None, hours=None):
    if hours:
        return capacity.can_take(db, practice=practice or "ir", hours=float(hours), weeks=min(int(weeks or 2), 4))
    return capacity.team(db, weeks=weeks or 4, practice=practice)


@tool("set_capacity", "Set a person's bookable hours per week and the practices they work in (admins).",
      S(**{"person!": WHO}, weekly_hours=NUM, practices=STR, active=BOOL, name=STR), write=True)
def t_set_capacity(db, ident, person, **f):
    if ident.role != "admin":
        raise ServiceError("Only an admin sets capacity", 403)
    row = capacity.set_capacity(db, _who(ident, person), **f)
    return {"email": row.email, "weekly_hours": row.weekly_hours, "practices": row.practices, "active": row.active}


# ---------------------------------------------------------------- metrics
@tool("portfolio_metrics", "Delivery metrics across engagements: time to contain, time to report, cycle time, "
      "on-time close, days per phase against template targets, budget variance, scope growth, task and milestone "
      "on-time rates; by practice and engagement type. Give an engagement for one engagement's numbers.",
      S(days=INT, practice=PRACTICE, type=STR, engagement=ENG, include_engagements=BOOL))
def t_metrics(db, ident, days=90, practice=None, type=None, engagement=None, include_engagements=False):
    if engagement:
        e = service.find_engagement(db, engagement)
        hrs = None
        if e.harvest_project_id and harvest.configured():
            try:
                hrs = harvest.project_hours(e.harvest_project_id)["total_hours"]
            except harvest.HarvestError:
                pass
        return metrics.engagement_metrics(db, e, hrs)
    out = metrics.portfolio(db, days=days or 90, practice=practice, engagement_type=type)
    if not include_engagements:
        out.pop("engagements", None)
    return out


# ---------------------------------------------------------------- change control
@tool("request_change", "Raise a change request against an engagement's sold scope: hours to add (or remove), "
      "days to move the end date, the reason, and who at the client agreed. A second person approves it.",
      S(**{"engagement!": ENG, "title!": STR}, hours_delta=NUM, days_delta=INT, description=STR,
        reason={"type": "string", "enum": ["client_request", "scope_discovery", "new_systems", "schedule", "other"]},
        client_approval=STR), write=True)
def t_request_change(db, ident, engagement, title, **f):
    e = service.find_engagement(db, engagement)
    return changes.cr_dict(changes.request(db, ident.email, e, title=title, **f))


@tool("decide_change", "Approve, reject or withdraw a change request. Approval moves the engagement's budget and "
      "end date; the baseline is kept.",
      S(**{"engagement!": ENG, "change!": {"type": "string", "description": "CR-2 or 2"},
           "decision!": {"type": "string", "enum": ["approve", "reject", "withdraw"]}}, note=STR,
        client_approval=STR), write=True)
def t_decide_change(db, ident, engagement, change, decision, note="", client_approval=None):
    e = service.find_engagement(db, engagement)
    cr = changes.decide(db, ident.email, ident.role, changes.find(db, e, change), decision, note, client_approval)
    return {**changes.cr_dict(cr), "scope": changes.scope_summary(db, e)}


@tool("list_changes", "Change requests, for one engagement (with its baseline against current scope) or across "
      "all, filtered by status.", S(engagement=ENG, status={"type": "string", "enum": ["requested", "approved",
                                                                                       "rejected", "withdrawn",
                                                                                       "all"]}))
def t_list_changes(db, ident, engagement=None, status="all"):
    e = service.find_engagement(db, engagement) if engagement else None
    out = {"changes": [changes.cr_dict(c) for c in changes.list_for(db, engagement=e, status=status)]}
    if e:
        out["scope"] = changes.scope_summary(db, e)
    return out


# ---------------------------------------------------------------- alerts
@tool("list_alerts", "Open delivery alerts: overdue and stuck tasks, WIP limits, budget burn and scope creep, "
      "engagements near or past their end, phases past target, overdue milestones, pending change requests, "
      "failed SharePoint copies. Yours by default; scope 'all' for everyone's.",
      S(scope={"type": "string", "enum": ["mine", "all"]}, severity={"type": "string",
                                                                     "enum": ["high", "medium", "low"]},
        engagement=ENG, refresh=BOOL))
def t_list_alerts(db, ident, scope="mine", severity=None, engagement=None, refresh=False):
    if refresh:
        alerts_mod.sync(db)
    eng = service.find_engagement(db, engagement) if engagement else None
    rows = alerts_mod.open_alerts(db, owner=ident.email if scope != "all" and not eng else None,
                                  severity=severity, engagement_id=eng.id if eng else None)
    return {"count": len(rows), "alerts": [alerts_mod.alert_dict(a) for a in rows]}


@tool("acknowledge_alert", "Mark an alert as seen. It stays open until the condition clears.",
      S(**{"key!": STR}), write=True)
def t_ack(db, ident, key):
    return alerts_mod.alert_dict(alerts_mod.ack(db, ident.email, key))


# ---------------------------------------------------------------- closeout and invoicing
@tool("closeout", "An engagement's closeout checklist: view it, check or uncheck an item (by number or text), "
      "or add one. The engagement cannot be closed with items open unless forced.",
      S(**{"engagement!": ENG}, action={"type": "string", "enum": ["view", "check", "uncheck", "add"]},
        item=STR))
def t_closeout(db, ident, engagement, action="view", item=None):
    e = service.find_engagement(db, engagement)
    if action == "view":
        return {**billing.closeout(e), "invoices": billing.invoices_for(db, e)}
    if ident.is_viewer:
        raise ServiceError("Read-only access", 403)
    if action == "add":
        return billing.add_item(db, ident.email, e, item or "")
    return billing.set_item(db, ident.email, e, item, done=action == "check")


@tool("uninvoiced_time", "Uninvoiced billable hours and amount in Harvest for an engagement's project.",
      S(**{"engagement!": ENG}, start=DATE, end=DATE))
def t_uninvoiced(db, ident, engagement, start=None, end=None):
    return billing.uninvoiced(db, service.find_engagement(db, engagement), start, end)


@tool("draft_invoice", "Create a DRAFT invoice in Harvest for an engagement: hourly from its uninvoiced time and "
      "expenses in the period, or a fixed fee. Never sends it; a person reviews and sends it in Harvest. PM of the "
      "engagement or admin only. Confirm the period and amount with the PM first.",
      S(**{"engagement!": ENG}, start=DATE, end=DATE,
        summary_type={"type": "string", "enum": ["task", "people", "project", "detailed"]}, notes=STR,
        payment_term={"type": "string", "enum": ["upon receipt", "net 15", "net 30", "net 45", "net 60"]},
        fixed_amount={"type": "number", "description": "Fixed-fee amount instead of importing time"}),
      write=True)
def t_draft_invoice(db, ident, engagement, **f):
    return billing.draft_invoice(db, ident.email, ident.role, service.find_engagement(db, engagement), **f)


# ---------------------------------------------------------------- dispatch
def call_tool(ident: Identity, name: str, args: dict) -> dict:
    t = TOOLS.get(name)
    if t is None:
        return _text_result(f"Unknown tool '{name}'", error=True)
    if t.write and ident.is_viewer:
        return _text_result("You have read-only (viewer) access to Project Management, so this tool is not "
                            "available. Ask a platform admin for analyst access.", error=True)
    props = t.schema.get("properties", {})
    unknown = [k for k in (args or {}) if k not in props]
    if unknown:
        return _text_result(f"Unknown argument(s) for {name}: {', '.join(unknown)}", error=True)
    missing = [k for k in t.schema.get("required", []) if (args or {}).get(k) in (None, "")]
    if missing:
        return _text_result(f"Missing required argument(s) for {name}: {', '.join(missing)}", error=True)
    db = SessionLocal()
    try:
        out = t.fn(db, ident, **(args or {}))
        if t.write:
            db.add(AuditLog(actor=ident.email, action=f"mcp.{name}",
                            detail=json.dumps(args, default=str)[:4000]))
        db.commit()
        return {"content": [{"type": "text", "text": json.dumps(out, default=str, indent=1)}],
                "structuredContent": out if isinstance(out, dict) else {"result": out}}
    except ServiceError as e:
        db.rollback()
        return _text_result(e.message, error=True)
    except harvest.HarvestError as e:
        db.rollback()
        return _text_result(str(e), error=True)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        log.exception("mcp tool %s failed", name)
        return _text_result(f"{name} failed: {type(e).__name__}", error=True)
    finally:
        db.close()


def _text_result(text: str, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": error}


def _rpc_error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def handle(ident: Identity, msg: dict) -> dict | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return _rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
    mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:  # a notification
        return None
    if method == "initialize":
        asked = params.get("protocolVersion")
        version = asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "Vendetta Project Management", "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        tools = [t.spec() for t in TOOLS.values() if not (t.write and ident.is_viewer)]
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _rpc_error(mid, -32602, "arguments must be an object")
        return {"jsonrpc": "2.0", "id": mid, "result": call_tool(ident, name, args)}
    if method in ("resources/list", "prompts/list"):
        key = method.split("/")[0]
        return {"jsonrpc": "2.0", "id": mid, "result": {key: []}}
    return _rpc_error(mid, -32601, f"Method not found: {method}")


def _unauthorized(request: Request, error: str = "invalid_token") -> Response:
    hdr = f'Bearer resource_metadata="{oauth.resource_metadata_url(request)}", scope="{oauth.SCOPE}"'
    if error:
        hdr += f', error="{error}"'
    return JSONResponse({"error": error or "unauthorized"}, status_code=401, headers={"WWW-Authenticate": hdr})


@router.post("/mcp")
async def mcp_post(request: Request):
    authz = request.headers.get("authorization", "")
    if not authz.startswith("Bearer "):
        return _unauthorized(request, "")
    ident = oauth.identity_from_token(authz[7:].strip())
    if ident is None or not ident.is_internal:
        return _unauthorized(request)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(_rpc_error(None, -32700, "Parse error"), status_code=400)
    if isinstance(body, list):
        replies = [r for r in (handle(ident, m) for m in body) if r is not None]
        return JSONResponse(replies) if replies else Response(status_code=202)
    reply = handle(ident, body)
    if reply is None:
        return Response(status_code=202)
    return JSONResponse(reply)


@router.get("/mcp")
def mcp_get():
    return Response(status_code=405, headers={"Allow": "POST"})


@router.delete("/mcp")
def mcp_delete():
    return Response(status_code=405, headers={"Allow": "POST"})
