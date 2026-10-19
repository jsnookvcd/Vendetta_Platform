"""Engagement templates: the repeatable delivery method.

A template carries the standard task set for one kind of engagement, each task with
an owner by role ("pm", "lead", or a person) and a due offset in days from the
engagement start; the client milestones; a default budget and duration; target days
per practice-board phase (alerts flag an engagement that sits past them); and the
closeout checklist. Applying a template to an engagement lays all of that onto its
task board, so every BEC, every ransomware case and every tabletop starts the same
way. PMs edit templates, and can save a finished engagement's board as a new one.

The built-in set below is seeded once and can be edited like any other.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import DEFAULT_CLOSEOUT, IR_WORKSTREAMS, PRACTICES, PRIORITIES
from .db import Card, Engagement, Milestone, Template, utcnow

SC, FA, RR, NL, RH = IR_WORKSTREAMS


def _t(title, owner="lead", offset=0, est=None, ws=None, column=None, checklist=None, priority="normal", labels=None):
    lab = list(labels or [])
    if ws:
        lab.insert(0, ws)
    out = {"title": title, "owner": owner, "offset_days": offset, "labels": lab, "priority": priority}
    if est is not None:
        out["estimate_hours"] = est
    if column:
        out["column"] = column
    if checklist:
        out["checklist"] = checklist
    return out


def _m(title, offset, ws="", visible=True):
    return {"title": title, "offset_days": offset, "workstream": ws, "client_visible": visible}


IR_PHASES_FAST = {"Intake": 1, "Engaged": 1, "Scoping and Containment": 2, "Forensics and Analysis": 6,
                  "Recovery and Restoration": 3, "Notification and Legal": 3, "Reporting": 3, "Closeout and Billing": 5}
IR_PHASES_MAJOR = {"Intake": 1, "Engaged": 1, "Scoping and Containment": 4, "Forensics and Analysis": 12,
                   "Recovery and Restoration": 10, "Notification and Legal": 7, "Reporting": 5,
                   "Closeout and Billing": 7}
PS_PHASES = {"Intake": 3, "Scoping": 5, "SOW Out": 7, "Scheduled": 14, "In Delivery": 21, "In Review": 5,
             "Delivered": 5, "Invoicing": 7}

BUILTIN = [
    {
        "key": "bec", "name": "Business email compromise (Microsoft 365)", "practice": "ir",
        "description": "Account takeover in M365: contain the identity, scope mailbox access from the audit "
                       "logs, trace fraudulent payments, and report on data exposure.",
        "budget_hours": 40, "duration_days": 14, "phase_days": IR_PHASES_FAST,
        "tasks": [
            _t("Kickoff call: scope, counsel, privilege and insurer", "pm", 0, 1, SC, priority="high"),
            _t("Send preservation and legal hold notice", "pm", 0, 0.5, NL),
            _t("Obtain tenant access (Global Reader, Exchange and audit roles)", "lead", 0, 0.5, SC, priority="high"),
            _t("Reset credentials, revoke sessions and enforce MFA", "lead", 0, 1, SC, priority="urgent"),
            _t("Remove malicious inbox rules, forwarding and OAuth grants", "lead", 0, 1, SC, priority="urgent"),
            _t("Collect UAL, sign-in logs and message trace", "lead", 1, 4, FA,
               checklist=["Export Unified Audit Log", "Export Entra sign-in logs", "Message trace", "Hash and log exports"]),
            _t("Analyze mailbox access (MailItemsAccessed) and attacker activity", "lead", 3, 8, FA),
            _t("Identify fraudulent payment requests and alert the bank fraud team", "pm", 1, 1, RR, priority="high"),
            _t("Data exposure review of accessed items", "lead", 5, 8, NL),
            _t("Draft findings report", "lead", 7, 6, NL),
            _t("Peer review the report", "pm", 8, 1.5, NL),
            _t("Deliver the report and hold the readout", "pm", 10, 1.5, NL),
            _t("Hardening recommendations: conditional access, mailbox auditing, MFA strength", "lead", 10, 2, RH),
        ],
        "milestones": [_m("Account contained", 1, SC), _m("Log collection complete", 2, FA),
                       _m("Scope of mailbox access determined", 6, FA), _m("Final report delivered", 10, NL)],
    },
    {
        "key": "ransomware", "name": "Ransomware response", "practice": "ir",
        "description": "Encryption event: contain and preserve, find initial access and exfiltration, support "
                       "recovery and notification, and harden.",
        "budget_hours": 120, "duration_days": 30, "phase_days": IR_PHASES_MAJOR,
        "tasks": [
            _t("Kickoff call: scope, counsel, insurer panel approval", "pm", 0, 1.5, SC, priority="urgent"),
            _t("Send preservation and legal hold notice", "pm", 0, 0.5, NL),
            _t("Isolate affected segments and block known attacker infrastructure", "lead", 0, 3, SC, priority="urgent"),
            _t("Deploy EDR to every reachable endpoint", "lead", 0, 4, SC, priority="urgent"),
            _t("Preserve evidence before rebuild: memory and disk images of key systems", "lead", 1, 8, FA,
               priority="high", checklist=["Domain controllers", "Patient zero candidates", "File servers",
                                           "Hash and log every image"]),
            _t("Reset credentials, including krbtgt twice", "lead", 1, 3, SC, priority="high"),
            _t("Identify the ransomware variant and check for a decryptor", "lead", 1, 2, FA),
            _t("Coordinate threat actor communication through counsel", "pm", 1, 3, NL),
            _t("Assess backup integrity and recovery points", "lead", 1, 4, RR, priority="high"),
            _t("Identify initial access and patient zero", "lead", 3, 12, FA),
            _t("Exfiltration analysis: what left, when, and where to", "lead", 5, 12, FA),
            _t("Watch leak sites for the client's data", "lead", 2, 2, NL),
            _t("Restoration plan and priority system order", "pm", 3, 4, RR),
            _t("Support notification analysis for counsel", "lead", 12, 8, NL),
            _t("Draft findings report", "lead", 18, 12, NL),
            _t("Peer review the report", "pm", 20, 3, NL),
            _t("Executive readout", "pm", 22, 2, NL),
            _t("Hardening plan: identity, EDR coverage, backups, external exposure", "lead", 22, 6, RH),
        ],
        "milestones": [_m("Environment contained", 3, SC), _m("Evidence preserved", 3, FA),
                       _m("Initial access identified", 10, FA), _m("Critical systems restored", 14, RR),
                       _m("Exfiltration scope determined", 14, FA), _m("Final report delivered", 22, NL)],
    },
    {
        "key": "malware-analysis", "name": "Malware analysis", "practice": "ir",
        "description": "A sample or suspicious binary: chain of custody, static and dynamic analysis, IOCs, "
                       "a hunt across EDR, and a report.",
        "budget_hours": 24, "duration_days": 7, "phase_days": IR_PHASES_FAST,
        "tasks": [
            _t("Acquire the sample with chain of custody", "lead", 0, 1, FA, priority="high"),
            _t("Static analysis", "lead", 1, 4, FA),
            _t("Dynamic analysis in the sandbox", "lead", 2, 6, FA),
            _t("Extract IOCs and detection logic", "lead", 3, 2, FA),
            _t("Hunt the IOCs across the client's EDR", "lead", 3, 4, SC),
            _t("Draft the analysis report", "lead", 4, 4, NL),
            _t("Deliver the report", "pm", 5, 1, NL),
        ],
        "milestones": [_m("Sample received", 0, FA), _m("Analysis complete", 4, FA), _m("Report delivered", 5, NL)],
    },
    {
        "key": "ir-general", "name": "Incident response (general)", "practice": "ir",
        "description": "Any incident that does not fit a more specific template.",
        "budget_hours": 60, "duration_days": 21, "phase_days": IR_PHASES_FAST,
        "tasks": [
            _t("Kickoff call: scope, counsel, privilege and insurer", "pm", 0, 1, SC, priority="high"),
            _t("Send preservation and legal hold notice", "pm", 0, 0.5, NL),
            _t("Containment actions", "lead", 0, 4, SC, priority="high"),
            _t("Collect and preserve evidence", "lead", 1, 6, FA),
            _t("Analysis", "lead", 3, 16, FA),
            _t("Recovery support", "lead", 5, 6, RR),
            _t("Draft findings report", "lead", 10, 8, NL),
            _t("Deliver the report and hold the readout", "pm", 14, 2, NL),
            _t("Hardening recommendations", "lead", 14, 3, RH),
        ],
        "milestones": [_m("Contained", 2, SC), _m("Root cause identified", 10, FA), _m("Final report delivered", 14, NL)],
    },
    {
        "key": "tabletop", "name": "Tabletop exercise", "practice": "proserv",
        "description": "Design, run and report a tabletop exercise.",
        "budget_hours": 40, "duration_days": 30, "phase_days": PS_PHASES,
        "tasks": [
            _t("Kickoff: objectives, audience, regulatory drivers", "pm", 0, 1.5),
            _t("Scenario design", "lead", 3, 6),
            _t("Draft injects and facilitator guide", "lead", 7, 8),
            _t("Client review of the scenario", "pm", 14, 1),
            _t("Logistics: room, attendees, remote access", "pm", 14, 1),
            _t("Facilitate the exercise", "lead", 21, 6),
            _t("Draft the after-action report", "lead", 23, 8),
            _t("Deliver the after-action report and readout", "pm", 28, 2),
        ],
        "milestones": [_m("Scenario approved", 14), _m("Exercise held", 21), _m("After-action report delivered", 28)],
    },
    {
        "key": "vciso-onboarding", "name": "vCISO onboarding", "practice": "proserv",
        "description": "First 60 days of a vCISO retainer.",
        "budget_hours": 60, "duration_days": 60, "phase_days": PS_PHASES,
        "tasks": [
            _t("Onboarding call and access", "pm", 0, 1.5),
            _t("Stakeholder interviews", "lead", 5, 8),
            _t("Policy and control inventory", "lead", 10, 8),
            _t("Risk assessment", "lead", 20, 16),
            _t("Security roadmap", "lead", 40, 10),
            _t("Present roadmap to leadership", "pm", 50, 2),
            _t("Set the monthly cadence and reporting", "pm", 55, 1),
        ],
        "milestones": [_m("Onboarding complete", 5), _m("Risk assessment delivered", 35), _m("Roadmap presented", 50)],
    },
    {
        "key": "pentest", "name": "Penetration test", "practice": "proserv",
        "description": "Scoped test with rules of engagement, testing window, report and retest.",
        "budget_hours": 60, "duration_days": 30, "phase_days": PS_PHASES,
        "tasks": [
            _t("Scoping call and rules of engagement signed", "pm", 0, 1.5, priority="high"),
            _t("Authorization letter on file", "pm", 1, 0.5, priority="high"),
            _t("Reconnaissance", "lead", 5, 6),
            _t("Testing window", "lead", 7, 24),
            _t("Findings review", "lead", 14, 3),
            _t("Draft the report", "lead", 16, 10),
            _t("Deliver the report and readout", "pm", 21, 2),
            _t("Retest remediated findings", "lead", 28, 6),
        ],
        "milestones": [_m("Rules of engagement signed", 1), _m("Testing complete", 14), _m("Report delivered", 21),
                       _m("Retest complete", 28)],
    },
    {
        "key": "pre-ransomware", "name": "Pre-Ransomware Assessment", "practice": "proserv",
        "description": "The channel entry assessment: exposure, identity, backups and EDR coverage, scored.",
        "budget_hours": 32, "duration_days": 14, "phase_days": PS_PHASES,
        "tasks": [
            _t("Intake questionnaire and access", "pm", 0, 1),
            _t("External exposure scan", "lead", 1, 4),
            _t("Identity and M365 review", "lead", 2, 6),
            _t("Backup and recovery review", "lead", 3, 4),
            _t("EDR coverage review", "lead", 3, 3),
            _t("Score and draft the report", "lead", 7, 8),
            _t("Readout with the client and the MSP", "pm", 10, 2),
        ],
        "milestones": [_m("Data collection complete", 5), _m("Report delivered", 10)],
    },
]

BUILTIN_KEYS = {b["key"] for b in BUILTIN}


def seed(db: Session) -> None:
    for b in BUILTIN:
        if db.execute(select(Template).where(Template.key == b["key"])).first():
            continue
        db.add(Template(key=b["key"], name=b["name"], practice=b["practice"], description=b["description"],
                        budget_hours=b["budget_hours"], duration_days=b["duration_days"], tasks=b["tasks"],
                        milestones=b["milestones"], phase_days=b["phase_days"],
                        closeout=list(DEFAULT_CLOSEOUT[b["practice"]]), builtin=True, updated_by="system"))
    db.flush()


def find(db: Session, ref: str) -> Template:
    from .service import ServiceError

    ref = (ref or "").strip()
    t = db.get(Template, ref) or db.execute(select(Template).where(func.lower(Template.key) == ref.lower())).scalar_one_or_none()
    if t:
        return t
    rows = db.execute(select(Template).where(Template.name.ilike(f"%{ref}%"), Template.active.is_(True))).scalars().all()
    if len(rows) == 1:
        return rows[0]
    keys = ", ".join(r.key for r in db.execute(select(Template).where(Template.active.is_(True))).scalars())
    raise ServiceError(f"No single template matches '{ref}'. Templates: {keys}", 404)


def template_dict(t: Template, *, full: bool = True) -> dict:
    out = {"key": t.key, "name": t.name, "practice": t.practice, "description": t.description,
           "budget_hours": t.budget_hours, "duration_days": t.duration_days, "task_count": len(t.tasks or []),
           "milestone_count": len(t.milestones or []), "builtin": t.builtin, "active": t.active}
    if full:
        out.update(tasks=t.tasks, milestones=t.milestones, phase_days=t.phase_days, closeout=t.closeout,
                   updated_by=t.updated_by, updated_at=t.updated_at.isoformat() if t.updated_at else None)
    return out


def _clean_tasks(items) -> list[dict]:
    from .service import ServiceError

    out = []
    for i, it in enumerate(items or []):
        if isinstance(it, str):
            it = {"title": it}
        title = str(it.get("title") or "").strip()
        if not title:
            raise ServiceError(f"Template task {i + 1} has no title")
        pr = str(it.get("priority") or "normal").lower()
        if pr not in PRIORITIES:
            raise ServiceError(f"Template task '{title}': priority must be one of {', '.join(PRIORITIES)}")
        row = {"title": title[:400], "owner": str(it.get("owner") or "").strip().lower(),
               "offset_days": int(it.get("offset_days") or 0), "priority": pr,
               "labels": [str(x).strip() for x in (it.get("labels") or []) if str(x).strip()][:12]}
        if it.get("estimate_hours") not in (None, ""):
            row["estimate_hours"] = float(it["estimate_hours"])
        if it.get("column"):
            row["column"] = str(it["column"])
        if it.get("checklist"):
            row["checklist"] = [str(x) for x in it["checklist"] if str(x).strip()]
        out.append(row)
    return out


def _clean_milestones(items) -> list[dict]:
    out = []
    for it in items or []:
        if isinstance(it, str):
            it = {"title": it}
        if str(it.get("title") or "").strip():
            out.append({"title": str(it["title"]).strip()[:300], "offset_days": int(it.get("offset_days") or 0),
                        "workstream": str(it.get("workstream") or ""),
                        "client_visible": bool(it.get("client_visible", True))})
    return out


def save(db: Session, actor: str, *, key: str, name: str | None = None, practice: str | None = None,
         description: str | None = None, budget_hours=None, duration_days=None, tasks=None, milestones=None,
         phase_days=None, closeout=None, active: bool | None = None) -> Template:
    """Create a template, or update the one with this key (only the fields given)."""
    from .service import ServiceError

    key = (key or "").strip().lower().replace(" ", "-")
    if not key:
        raise ServiceError("A template needs a key, like 'bec' or 'tabletop'")
    t = db.execute(select(Template).where(Template.key == key)).scalar_one_or_none()
    if t is None:
        if not name or practice not in PRACTICES:
            raise ServiceError("A new template needs a name and a practice (ir or proserv)")
        t = Template(key=key, name=name, practice=practice, closeout=list(DEFAULT_CLOSEOUT[practice]))
        db.add(t)
    if name is not None:
        t.name = name.strip()
    if practice is not None:
        if practice not in PRACTICES:
            raise ServiceError("Practice must be ir or proserv")
        t.practice = practice
    if description is not None:
        t.description = description
    if budget_hours is not None:
        t.budget_hours = float(budget_hours) if budget_hours != "" else None
    if duration_days is not None:
        t.duration_days = int(duration_days) if duration_days != "" else None
    if tasks is not None:
        t.tasks = _clean_tasks(tasks)
    if milestones is not None:
        t.milestones = _clean_milestones(milestones)
    if phase_days is not None:
        t.phase_days = {str(k): int(v) for k, v in dict(phase_days).items() if v not in (None, "")}
    if closeout is not None:
        t.closeout = [str(x).strip() for x in closeout if str(x).strip()]
    if active is not None:
        t.active = bool(active)
    t.updated_by, t.updated_at = actor, utcnow()
    db.flush()
    return t


def from_engagement(db: Session, actor: str, eng: Engagement, *, key: str, name: str) -> Template:
    """Capture an engagement's task board and milestones as a template, with each
    task's due date turned back into an offset from the engagement start and the
    PM and lead turned back into roles."""
    from . import service

    start = eng.starts_on or eng.created_at.date()
    board = service.engagement_board(db, eng)
    tasks = []
    cards = db.execute(select(Card).where(Card.board_id == board.id, Card.archived.is_(False))
                       .order_by(Card.due_on.is_(None), Card.due_on, Card.ref)).scalars()
    for c in cards:
        owner = "pm" if c.assignee and c.assignee == eng.pm_email else \
            "lead" if c.assignee and c.assignee == eng.lead_email else ""
        tasks.append({"title": c.title, "owner": owner, "priority": c.priority,
                      "offset_days": (c.due_on - start).days if c.due_on else 0,
                      "labels": [x for x in c.labels or [] if x != "action item"],
                      **({"estimate_hours": c.estimate_hours} if c.estimate_hours else {}),
                      **({"checklist": [i["text"] for i in c.checklist]} if c.checklist else {})})
    ms = [{"title": m.title, "workstream": m.workstream, "client_visible": m.client_visible,
           "offset_days": (m.due_on - start).days if m.due_on else 0}
          for m in db.execute(select(Milestone).where(Milestone.engagement_id == eng.id)
                              .order_by(Milestone.position)).scalars()]
    dur = (eng.ends_on - start).days if eng.ends_on else None
    return save(db, actor, key=key, name=name, practice=eng.practice,
                description=f"Captured from {eng.code} {eng.name}", budget_hours=eng.budget_hours,
                duration_days=dur, tasks=tasks, milestones=ms,
                closeout=[i["text"] for i in eng.closeout or []] or None)


def apply(db: Session, actor: str, eng: Engagement, t: Template, *, start: dt.date | None = None) -> dict:
    """Lay a template onto an engagement: tasks, milestones, closeout, and any
    budget or end date the engagement does not already have."""
    from . import service

    if t.practice != eng.practice:
        raise service.ServiceError(f"Template '{t.key}' is for {t.practice}; {eng.code} is {eng.practice}")
    start = start or eng.starts_on or dt.date.today()
    if not eng.starts_on:
        eng.starts_on = start
    if eng.budget_hours is None and t.budget_hours:
        eng.budget_hours = t.budget_hours
    if eng.ends_on is None and t.duration_days:
        eng.ends_on = start + dt.timedelta(days=t.duration_days)
    if eng.baseline_budget_hours is None:
        eng.baseline_budget_hours = eng.budget_hours
    if eng.baseline_ends_on is None:
        eng.baseline_ends_on = eng.ends_on
    eng.engagement_type, eng.template_id = t.key, t.id

    def owner(role: str) -> str | None:
        role = (role or "").strip().lower()
        if role == "pm":
            return eng.pm_email or None
        if role == "lead":
            return eng.lead_email or eng.pm_email or None
        return role if "@" in role else None

    made = []
    for it in t.tasks or []:
        made.append(service.create_task(
            db, actor, eng, title=it["title"], assignee=owner(it.get("owner", "")),
            due_on=start + dt.timedelta(days=int(it.get("offset_days") or 0)), priority=it.get("priority"),
            labels=it.get("labels"), column=it.get("column") or None, estimate_hours=it.get("estimate_hours"),
            checklist=it.get("checklist"), description=f"From the {t.name} template"))
    existing = db.scalar(select(func.count(Milestone.id)).where(Milestone.engagement_id == eng.id)) or 0
    for i, m in enumerate(t.milestones or []):
        db.add(Milestone(engagement_id=eng.id, title=m["title"], workstream=m.get("workstream", ""),
                         due_on=start + dt.timedelta(days=int(m.get("offset_days") or 0)),
                         client_visible=bool(m.get("client_visible", True)), position=existing + i))
    if not eng.closeout:
        eng.closeout = [{"key": f"c{i + 1}", "text": x, "done": False} for i, x in enumerate(t.closeout or [])]
    db.flush()
    return {"template": t.key, "tasks_added": len(made), "milestones_added": len(t.milestones or []),
            "starts_on": start.isoformat(), "ends_on": eng.ends_on.isoformat() if eng.ends_on else None,
            "budget_hours": eng.budget_hours}
