"""Project kickoff: stand an engagement up across every tool in one go.

A PM fills in one form (or asks Claude): practice, client, engagement, template,
team, budget and billing. The kickoff then

  1. opens the engagement here, on its practice board, with its task board laid out
     from the template;
  2. links or opens the platform record (an IR hub case, or the OSP engagement) so
     client milestones reach the client portal;
  3. finds or creates the Harvest client, creates the Harvest project with its budget
     and billing, assigns the practice's tasks and the team (PM as project manager);
  4. adds the engagement team to the practice's parent team ("Vendetta Incident
     Response" or "Vendetta Professional Services") and opens a private channel for
     the engagement in it, "<code> <codename or client>", in the threads layout,
     with the team as members and the PM as owner;
  5. lays out the folder tree in the channel's own SharePoint site and points this
     engagement's meeting notes at it;
  6. gives the engagement its email address, a plus address on the practice's
     shared mailbox, with a mail folder and an inbox rule that files its mail;
  7. adds tabs to the case channel: this engagement's board and the Vendetta Time
     tab, locked to the engagement;
  8. makes sure the practice team has its Time Entry channel, with an unlocked
     Vendetta Time tab for logging time across engagements;
  9. registers the engagement in Vendetta Time (Projects row with the Harvest
     project id, TabContexts row that locks the case channel's tab to it);
 10. opens the service desk ticket (once a ticketing system is chosen);
 11. drafts the client kickoff email in the PM's mailbox, CC the engagement address;
 12. posts the kickoff, with every link, to the delivery channel.

Every step is idempotent and records what it did. A step that waits on Microsoft
365 (a new private channel's site takes minutes) is retried in the background; a
failed step is retried from the kickoff page without repeating the steps that
worked.
"""
from __future__ import annotations

import datetime as dt
import html
import logging
import re
import threading
import time

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import alerts as alerts_mod
from . import harvest, integrations, m365, service, sharepoint, ticketing
from . import milestones as milestones_mod
from .config import (BILLING_TYPE_NAMES, BILLING_TYPES, PRACTICE_NAMES, kickoff_settings, settings)
from .db import AuditLog, Engagement, Kickoff, SessionLocal, utcnow
from .service import ServiceError

log = logging.getLogger(__name__)
cfg = kickoff_settings
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LEASE_SECONDS = 300

# key, label, steps it needs (ok or skipped) before it can run
STEPS: list[tuple[str, str, list[str]]] = [
    ("engagement", "Engagement, practice board card and task board", []),
    ("platform", "Platform record (IR hub case or OSP engagement)", ["engagement"]),
    ("harvest_client", "Harvest client", ["engagement"]),
    ("harvest_project", "Harvest project, budget and billing", ["harvest_client"]),
    ("harvest_tasks", "Harvest tasks", ["harvest_project"]),
    ("harvest_team", "Harvest team assignments", ["harvest_project"]),
    ("m365_team", "Engagement team added to the practice team", ["engagement"]),
    ("m365_channel", "Private engagement channel", ["m365_team"]),
    ("m365_site", "Channel files and folders", ["m365_channel"]),
    ("mailbox", "Engagement email address", ["engagement"]),
    ("teams_tabs", "Channel tabs (engagement board, Vendetta Time)", ["m365_channel", "m365_site"]),
    ("time_channel", "Practice Time Entry channel", ["m365_team"]),
    ("vendetta_time", "Vendetta Time project and tab link", ["engagement", "harvest_project", "m365_channel"]),
    ("ticket", "Service desk ticket", ["engagement"]),
    ("client_email", "Client kickoff email draft", ["engagement", "mailbox"]),
    ("announce", "Kickoff posted to the delivery channel", ["*"]),
]
LABELS = {k: label for k, label, _ in STEPS}
NEEDS = {k: needs for k, _, needs in STEPS}
SETTLED = {"ok", "skipped", "manual"}


class Skip(Exception):
    pass


# ---------------------------------------------------------------- request
def _emails(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = re.split(r"[,;\s]+", value)
    out = []
    for v in value:
        v = (v or "").strip().lower()
        if v and v not in out:
            if not EMAIL.match(v):
                raise ServiceError(f"'{v}' is not an email address")
            out.append(v)
    return out


def _team(value) -> list[dict]:
    """Team members as [{"email", "role"}], from dicts, "email:role" strings, or emails."""
    if not value:
        return []
    if isinstance(value, str):
        value = [v for v in re.split(r"[,;\n]+", value) if v.strip()]
    out: list[dict] = []
    for v in value:
        if isinstance(v, dict):
            email, role = v.get("email", ""), v.get("role", "")
        else:
            email, _, role = str(v).partition(":")
        email = email.strip().lower()
        if not email:
            continue
        if not EMAIL.match(email):
            raise ServiceError(f"'{email}' is not an email address")
        if all(m["email"] != email for m in out):
            out.append({"email": email, "role": (role or "member").strip().lower()[:30]})
    return out


def _bool(v, default=True) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _num(v, what: str) -> float | None:
    if v in (None, ""):
        return None
    try:
        n = float(v)
    except (TypeError, ValueError) as e:
        raise ServiceError(f"{what} must be a number") from e
    if n < 0:
        raise ServiceError(f"{what} cannot be negative")
    return n


def normalize(raw: dict, actor: str) -> dict:
    """Check and normalize what the PM asked for. Raises ServiceError with a message
    written for the PM."""
    practice = (raw.get("practice") or "").strip().lower()
    practice = {"ps": "proserv", "professional services": "proserv", "osp": "proserv",
                "incident response": "ir"}.get(practice, practice)
    if practice not in PRACTICE_NAMES:
        raise ServiceError("Practice must be ir (Incident Response) or proserv (Professional Services)")
    name = (raw.get("name") or "").strip()
    client = (raw.get("client") or "").strip()
    if not name:
        raise ServiceError("Name the engagement")
    if not client:
        raise ServiceError("Name the client (it becomes the Harvest client and names the Teams site)")
    billing = (raw.get("billing_type") or "hourly").strip().lower().replace(" ", "_").replace("-", "_")
    if billing not in BILLING_TYPES:
        raise ServiceError(f"Billing type must be one of: {', '.join(BILLING_TYPES)}")
    fee = _num(raw.get("fee"), "The fixed fee")
    if billing == "fixed_fee" and not fee:
        raise ServiceError("A fixed fee engagement needs the fee amount")
    pm = (raw.get("pm_email") or actor or "").strip().lower()
    if pm in ("me", "myself"):
        pm = actor
    lead = (raw.get("lead_email") or "").strip().lower()
    if lead in ("me", "myself"):
        lead = actor
    for who, v in (("PM", pm), ("Technical lead", lead)):
        if v and not EMAIL.match(v):
            raise ServiceError(f"{who} must be an email address")
    team = _team(raw.get("team"))
    always = cfg.ir_always_members if practice == "ir" else cfg.proserv_always_members
    for email in _emails(always):
        if all(m["email"] != email for m in team):
            team.append({"email": email, "role": "member"})
    for email, role in ((lead, "lead"), (pm, "pm")):
        if email:
            team = [m for m in team if m["email"] != email]
            team.insert(0, {"email": email, "role": role})
    opts = raw.get("options") or {}
    starts = service.parse_date(raw.get("starts_on"))
    ends = service.parse_date(raw.get("ends_on"))
    if starts and ends and ends < starts:
        raise ServiceError("The planned end is before the start")
    return {
        "practice": practice, "name": name[:300], "client": client[:200],
        "codename": (raw.get("codename") or "").strip()[:80],
        "template": (raw.get("template") or "").strip() or None,
        "pm_email": pm, "lead_email": lead, "team": team[:25],
        "budget_hours": _num(raw.get("budget_hours"), "Budget hours"),
        "billing_type": billing, "hourly_rate": _num(raw.get("hourly_rate"), "The hourly rate"), "fee": fee,
        "starts_on": starts.isoformat() if starts else None, "ends_on": ends.isoformat() if ends else None,
        "description": (raw.get("description") or "").strip()[:4000],
        "platform_ref": (raw.get("platform_ref") or "").strip()[:120],
        "severity": (raw.get("severity") or "high").strip().lower(),
        "harvest_project_id": str(raw.get("harvest_project_id") or "").strip(),
        "client_contacts": _emails(raw.get("client_contacts")),
        "ticket_ref": (raw.get("ticket_ref") or "").strip()[:120],
        "options": {k: _bool(opts.get(k, raw.get(k)), True)
                    for k in ("platform", "harvest", "m365", "vendetta_time", "client_email", "announce")},
    }


def _plan(req: dict) -> list[dict]:
    """The step list for a request, with steps that cannot apply skipped up front."""
    o = req["options"]
    harvest_on, graph_on = harvest.configured(), m365.configured()
    skip: dict[str, str] = {}
    if not o["platform"]:
        skip["platform"] = "Turned off for this kickoff"
    for k in ("harvest_client", "harvest_project", "harvest_tasks", "harvest_team"):
        if not o["harvest"]:
            skip[k] = "Turned off for this kickoff"
        elif not harvest_on:
            skip[k] = "Harvest is not connected (Integrations)"
    if o["harvest"] and harvest_on and req["harvest_project_id"]:
        skip["harvest_client"] = "Linking an existing Harvest project"
    team_id = cfg.ir_team_id if req["practice"] == "ir" else cfg.proserv_team_id
    mailbox = cfg.ir_mailbox if req["practice"] == "ir" else cfg.proserv_mailbox
    for k in ("m365_team", "m365_channel", "m365_site", "mailbox", "teams_tabs", "time_channel"):
        if not o["m365"]:
            skip[k] = "Turned off for this kickoff"
        elif not graph_on:
            skip[k] = "Microsoft Graph is not connected (Integrations)"
        elif k != "mailbox" and not team_id:
            skip[k] = ("No practice team set (KICKOFF_IR_TEAM_ID)" if req["practice"] == "ir"
                       else "No practice team set (KICKOFF_PROSERV_TEAM_ID)")
    if "mailbox" not in skip and not mailbox:
        skip["mailbox"] = ("No practice mailbox set (KICKOFF_IR_MAILBOX)" if req["practice"] == "ir"
                           else "No practice mailbox set (KICKOFF_PROSERV_MAILBOX)")
    if "time_channel" not in skip and not (o["vendetta_time"] and cfg.vtime_teams_app_id and cfg.vtime_tab_content_url):
        skip["time_channel"] = "Vendetta Time tab is not configured (KICKOFF_VTIME_TEAMS_APP_ID)"
    if not o["vendetta_time"]:
        skip["vendetta_time"] = "Turned off for this kickoff"
    elif not (cfg.vtime_site_url and graph_on):
        skip["vendetta_time"] = "Vendetta Time is not configured (KICKOFF_VTIME_SITE_URL)"
    if not o["client_email"]:
        skip["client_email"] = "Turned off for this kickoff"
    elif not req["client_contacts"]:
        skip["client_email"] = "No client contacts given"
    elif not (cfg.draft_client_email and graph_on):
        skip["client_email"] = "Client email drafts are off or Graph is not connected"
    if not o["announce"]:
        skip["announce"] = "Turned off for this kickoff"
    elif not alerts_mod.cfg.teams_webhook_url:
        skip["announce"] = "No delivery channel webhook (ALERT_TEAMS_WEBHOOK_URL)"
    return [{"key": k, "label": label, "status": "skipped" if k in skip else "pending",
             "detail": skip.get(k, ""), "link": "", "warn": "", "attempts": 0, "at": None}
            for k, label, _ in STEPS]


def start(db: Session, actor: str, raw: dict) -> Kickoff:
    """Record a kickoff. The caller commits, then calls run(kickoff.id)."""
    req = normalize(raw, actor)
    if req["template"]:
        from . import templates_lib
        t = templates_lib.find(db, req["template"])
        if t.practice != req["practice"]:
            raise ServiceError(f"Template '{t.key}' is for {PRACTICE_NAMES[t.practice]}")
        req["template"] = t.key
    k = Kickoff(request=req, steps=_plan(req), state={}, created_by=actor, status="running")
    db.add(k)
    db.add(AuditLog(actor=actor, action="kickoff.start", detail=f"{req['practice']} {req['client']}: {req['name']}"))
    db.flush()
    return k


# ---------------------------------------------------------------- running
def _claim(db: Session, kid: str, force: bool) -> bool:
    """Take the kickoff's lease so one worker runs it at a time, across processes."""
    cond = "" if force else " AND (next_run_at IS NULL OR next_run_at <= now())"
    row = db.execute(text("UPDATE kickoffs SET next_run_at = now() + make_interval(secs => :s) "
                          "WHERE id = :id AND status <> 'done'" + cond + " RETURNING id"),
                     {"s": LEASE_SECONDS, "id": kid}).first()
    db.commit()
    return row is not None


def run(kid: str, *, force: bool = False) -> Kickoff | None:
    """Run every step that is not finished. Returns the kickoff, or None when another
    worker holds it."""
    db = SessionLocal()
    try:
        if not _claim(db, kid, force):
            return db.get(Kickoff, kid)
        k = db.get(Kickoff, kid)
        _run(db, k)
        return k
    finally:
        db.close()


class Ctx:
    def __init__(self, db: Session, k: Kickoff):
        self.db, self.k, self.req = db, k, k.request
        self.actor = k.created_by
        self.state = dict(k.state or {})
        self._http: httpx.Client | None = None

    @property
    def eng(self) -> Engagement:
        e = self.db.get(Engagement, self.k.engagement_id) if self.k.engagement_id else None
        if e is None:
            raise ServiceError("The engagement has not been opened")
        return e

    @property
    def graph(self) -> httpx.Client:
        if self._http is None:
            self._http = m365._client()
        return self._http

    def close(self):
        if self._http is not None:
            self._http.close()


def _steps_by_key(k: Kickoff) -> dict[str, dict]:
    return {s["key"]: s for s in k.steps}


def _run(db: Session, k: Kickoff) -> None:
    ctx = Ctx(db, k)
    steps = [dict(s) for s in k.steps]
    by = {s["key"]: s for s in steps}
    try:
        for key, _, needs in STEPS:
            s = by[key]
            if s["status"] in SETTLED:
                continue
            if needs == ["*"]:
                open_ = [x for x in steps if x["key"] != key and x["status"] not in SETTLED | {"failed"}]
                if open_:
                    s.update(status="pending", detail="Posts once setup finishes")
                    continue
            else:
                blocked = [n for n in needs if by[n]["status"] not in SETTLED]
                if blocked:
                    s.update(status="pending",
                             detail="Waits on: " + ", ".join(LABELS[n] for n in blocked))
                    continue
            fn = STEP_FNS[key]
            s["attempts"] = int(s.get("attempts") or 0) + 1
            s["at"] = utcnow().isoformat()
            try:
                res = fn(ctx) or {}
                s.update(status=res.get("status", "ok"), detail=res.get("detail", ""), link=res.get("link", ""),
                         warn=res.get("warn", ""))
            except Skip as e:
                s.update(status="skipped", detail=str(e), warn="")
            except m365.Wait as e:
                if s["attempts"] >= cfg.max_attempts:
                    s.update(status="failed", detail=f"Timed out waiting: {e}")
                else:
                    s.update(status="waiting", detail=str(e))
            except ServiceError as e:
                db.rollback()
                s.update(status="failed", detail=e.message)
            except (harvest.HarvestError, m365.GraphError, sharepoint.SharePointError) as e:
                db.rollback()
                s.update(status="failed", detail=str(e))
            except httpx.HTTPError as e:
                db.rollback()
                s.update(status="failed", detail=f"Network error: {type(e).__name__}")
            except Exception as e:  # noqa: BLE001
                db.rollback()
                log.exception("kickoff %s step %s", k.id, key)
                s.update(status="failed", detail=f"Unexpected error: {type(e).__name__}: {e}"[:400])
            k = db.get(Kickoff, k.id)
            ctx.k = k
            k.steps = [dict(x) for x in steps]
            k.state = dict(ctx.state)
            k.updated_at = utcnow()
            db.commit()
    finally:
        ctx.close()
    sts = {s["status"] for s in steps}
    k = db.get(Kickoff, k.id)
    if "failed" in sts:
        k.status, k.next_run_at = "attention", None
    elif sts & {"waiting", "pending"}:
        k.status = "waiting"
        k.next_run_at = utcnow() + dt.timedelta(seconds=max(cfg.retry_seconds, 15))
    else:
        k.status, k.next_run_at = "done", None
        if k.finished_at is None:
            k.finished_at = utcnow()
            if k.engagement_id:
                eng = db.get(Engagement, k.engagement_id)
                card = service.practice_card(db, eng) if eng else None
                if card:
                    service._event(db, card, k.created_by, "updated", "kickoff complete")
    k.updated_at = utcnow()
    db.commit()


def retry(db: Session, actor: str, k: Kickoff, step: str | None = None) -> None:
    """Put failed (or one named) steps back to pending. The caller commits, then runs."""
    for s in k.steps:
        if (step and s["key"] == step) or (not step and s["status"] in ("failed", "waiting")):
            if step and s["status"] == "ok":
                continue
            s.update(status="pending", detail="", attempts=0)
    k.steps = [dict(s) for s in k.steps]
    k.status, k.next_run_at = "running", None
    db.add(AuditLog(actor=actor, action="kickoff.retry", detail=f"{k.id} {step or 'failed steps'}"))
    db.flush()


def mark_manual_done(db: Session, actor: str, k: Kickoff, step: str) -> None:
    for s in k.steps:
        if s["key"] == step:
            if s["status"] != "manual":
                raise ServiceError("Only a manual step can be marked done")
            s.update(status="ok", detail=f"Done, confirmed by {actor}", at=utcnow().isoformat())
    k.steps = [dict(s) for s in k.steps]
    db.flush()


def find(db: Session, ref: str) -> Kickoff:
    ref = (ref or "").strip()
    k = db.get(Kickoff, ref)
    if k:
        return k
    eng = service.find_engagement(db, ref)
    k = db.execute(select(Kickoff).where(Kickoff.engagement_id == eng.id)
                   .order_by(Kickoff.created_at.desc())).scalars().first()
    if k is None:
        raise ServiceError(f"{eng.code} has no kickoff", 404)
    return k


def kickoff_dict(db: Session, k: Kickoff) -> dict:
    eng = db.get(Engagement, k.engagement_id) if k.engagement_id else None
    r = k.request or {}
    return {"id": k.id, "status": k.status, "engagement": eng.code if eng else None,
            "engagement_id": k.engagement_id, "practice": r.get("practice"), "client": r.get("client"),
            "name": r.get("name"), "created_by": k.created_by, "created_at": k.created_at.isoformat(),
            "finished_at": k.finished_at.isoformat() if k.finished_at else None,
            "steps": [{"key": s["key"], "label": s["label"], "status": s["status"], "detail": s.get("detail", ""),
                       "warning": s.get("warn") or None, "link": s.get("link") or None} for s in k.steps],
            "links": links(db, k)}


def links(db: Session, k: Kickoff) -> dict:
    st = k.state or {}
    out = {}
    if k.engagement_id:
        out["engagement"] = _public(f"/engagements/{k.engagement_id}")
    for key, name in (("files_url", "sharepoint"), ("channel_url", "teams"), ("mail_address", "mailbox"),
                      ("harvest_project_id", "harvest_project_id"), ("platform_ref", "platform_ref"),
                      ("ticket_url", "ticket")):
        if st.get(key):
            out[name] = st[key]
    return out


def _public(path: str) -> str:
    return f"{settings.public_url.rstrip('/')}{path}" if settings.public_url else path


def recent(db: Session, limit: int = 20) -> list[Kickoff]:
    return list(db.execute(select(Kickoff).order_by(Kickoff.created_at.desc()).limit(limit)).scalars())


# ---------------------------------------------------------------- steps
def s_engagement(c: Ctx) -> dict:
    r = c.req
    if c.k.engagement_id:
        e = c.eng
    else:
        e = service.create_engagement(
            c.db, c.actor, practice=r["practice"], name=r["name"], client=r["client"], pm_email=r["pm_email"],
            lead_email=r["lead_email"] or None, description=r["description"], budget_hours=r["budget_hours"],
            starts_on=r["starts_on"], ends_on=r["ends_on"], template=r["template"],
            platform_ref=r["platform_ref"], harvest_project_id="")
        c.k.engagement_id = e.id
        c.db.flush()
    c.state["code"] = e.code
    tasks = service.engagement_dict(c.db, e)["tasks"]
    tpl = f" from the {r['template']} template" if r["template"] else ""
    return {"detail": f"{e.code} opened on the {PRACTICE_NAMES[e.practice]} board with {tasks['open']} "
                      f"task(s){tpl}", "link": f"/engagements/{e.id}"}


def s_platform(c: Ctx) -> dict:
    e, r = c.eng, c.req
    if e.platform_ref:
        res = milestones_mod.publish(c.db, e)
        c.state["platform_ref"] = e.platform_ref
        warn = "" if res.get("published") else res.get("reason", "")
        return {"detail": f"Linked to {e.platform_ref}", "warn": warn}
    if e.practice == "proserv":
        raise Skip("The Office of Special Projects opens its engagements in its own console. Add the OSP "
                   "engagement id as the platform reference to show milestones to the client.")
    if not settings.platform_hub_url:
        raise Skip("The IR hub is not configured (PLATFORM_HUB_URL)")
    plat_id = e.client.platform_client_id if e.client else ""
    payload = {"source_module": "project-management", "client": e.client_name, "platform_client_id": plat_id,
               "severity": r["severity"] if r["severity"] in ("low", "medium", "high", "critical") else "high",
               "summary": f"{e.name} ({e.code})", "workstream": "Scoping and Containment",
               "finding": {"title": f"Engagement kickoff: {e.name}", "module": "project-management",
                           "subject": {"client": e.client_name, "platform_client_id": plat_id}}}
    headers = {"X-Vendetta-Actor": "project-management"}
    if settings.platform_hub_token:
        headers["Authorization"] = f"Bearer {settings.platform_hub_token}"
    with httpx.Client(timeout=20.0, transport=milestones_mod.TRANSPORT, headers=headers) as http:
        resp = http.post(f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases", json=payload)
    if resp.status_code >= 400:
        raise ServiceError(f"The IR hub refused the case (HTTP {resp.status_code})")
    num = str(resp.json().get("case_id") or "")
    if not num:
        raise ServiceError("The IR hub did not return a case number")
    e.platform_ref = num
    c.state["platform_ref"] = num
    milestones_mod.publish(c.db, e)
    c.db.flush()
    return {"detail": f"IR hub case {num} opened and linked; client milestones publish to it"}


def s_harvest_client(c: Ctx) -> dict:
    client, created = harvest.find_or_create_client(c.req["client"])
    c.state["harvest_client_id"] = client["id"]
    c.state["client_name"] = client["name"]
    e = c.eng
    if not e.client and (e.client_name or "").lower() == (client["name"] or "").lower():
        e.client_name = client["name"]
        c.db.flush()
    return {"detail": f"{'Created' if created else 'Found'} Harvest client {client['name']}"}


def s_harvest_project(c: Ctx) -> dict:
    e, r = c.eng, c.req
    if r["harvest_project_id"]:
        service.update_engagement(c.db, c.actor, e, harvest_project_id=r["harvest_project_id"])
        c.state["harvest_project_id"] = e.harvest_project_id
        return {"detail": f"Linked existing Harvest project {e.harvest_project_name or e.harvest_project_id}"}
    if e.harvest_project_id:
        c.state["harvest_project_id"] = e.harvest_project_id
        return {"detail": f"Already linked to Harvest project {e.harvest_project_id}"}
    cid = c.state["harvest_client_id"]
    p = harvest.find_project_by_code(cid, e.code)
    created = p is None
    if created:
        notes = f"{PRACTICE_NAMES[e.practice]} engagement opened by kickoff. PM {e.pm_email}."
        if r.get("ticket_ref"):
            notes += f" Ticket {r['ticket_ref']}."
        p = harvest.create_project(
            client_id=cid, name=f"{e.code} {e.name}", code=e.code, billing_type=r["billing_type"],
            budget_hours=e.budget_hours, hourly_rate=r["hourly_rate"], fee=r["fee"], starts_on=e.starts_on,
            ends_on=e.ends_on, notes=notes, alert_pct=cfg.harvest_budget_alert_pct)
    service.update_engagement(c.db, c.actor, e, harvest_project_id=p["id"])
    c.state["harvest_project_id"] = p["id"]
    budget = f", {e.budget_hours:g} hour budget" if e.budget_hours else ""
    fee = f", fixed fee ${r['fee']:,.2f}" if r["billing_type"] == "fixed_fee" else ""
    return {"detail": f"{'Created' if created else 'Found'} {p['name']} "
                      f"({BILLING_TYPE_NAMES[r['billing_type']]}{fee}{budget})"}


def _names(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def s_harvest_tasks(c: Ctx) -> dict:
    names = _names(cfg.harvest_tasks_ir if c.eng.practice == "ir" else cfg.harvest_tasks_proserv)
    if not names:
        raise Skip("No Harvest tasks configured for this practice")
    res = harvest.assign_tasks(c.state["harvest_project_id"], names,
                               {n.lower() for n in _names(cfg.harvest_nonbillable_tasks)})
    if res["missing"] and len(res["missing"]) == len(names):
        raise ServiceError("None of the practice's Harvest tasks exist in Harvest: " + ", ".join(res["missing"]))
    warn = ("Not in Harvest, so not assigned: " + ", ".join(res["missing"])) if res["missing"] else ""
    return {"detail": f"Assigned {len(res['added'])} task(s)" if res["added"] else "Tasks already assigned",
            "warn": warn}


def s_harvest_team(c: Ctx) -> dict:
    people = [(m["email"], m["role"] == "pm") for m in c.req["team"]]
    if not people:
        raise Skip("No team named")
    res = harvest.assign_people(c.state["harvest_project_id"], people)
    warn = ("No Harvest user for: " + ", ".join(res["missing"])) if res["missing"] else ""
    return {"detail": f"Assigned {len(res['added'])} person(s); PM is project manager" if res["added"]
            else "Team already assigned", "warn": warn}


def _channel_label(c: Ctx) -> str:
    r, e = c.req, c.eng
    client = e.client.name if e.client else (c.state.get("client_name") or e.client_name or r["client"])
    return r["codename"] or client


def _team_id(c: Ctx) -> str:
    return cfg.ir_team_id if c.req["practice"] == "ir" else cfg.proserv_team_id


def s_m365_team(c: Ctx) -> dict:
    """Everyone on the engagement must be in the practice team before the private
    channel can take them."""
    r, http = c.req, c.graph
    team = m365.practice_team(http, _team_id(c))
    owners = list(dict.fromkeys([r["pm_email"]] + _emails(cfg.channel_owners)))
    members = [m["email"] for m in r["team"]]
    ids, missing = m365.resolve_users(http, list(dict.fromkeys(owners + members)))
    owner_ids = [ids[x] for x in owners if x in ids]
    member_ids = [ids[x] for x in members if x in ids and x not in owners]
    if not owner_ids:
        raise ServiceError(f"The PM {r['pm_email']} is not in the Microsoft 365 directory")
    added = m365.add_members(http, team["id"], owner_ids + member_ids)
    c.state.update(team_id=team["id"], team_name=team["name"], team_url=team["url"],
                   owner_ids=owner_ids, member_ids=member_ids)
    warns = []
    if missing:
        warns.append("Not in the directory, so not added: " + ", ".join(missing))
    n = len(team["channels"])
    if n >= cfg.channel_warn_at:
        warns.append(f"{team['name'] or 'The practice team'} holds {n} of {m365.CHANNEL_LIMIT} channels. "
                     "Plan the next practice team.")
    return {"detail": (f"Added {added} person(s) to {team['name']}" if added
                       else f"Everyone is already in {team['name']}"), "warn": "; ".join(warns),
            "link": team["url"]}


def s_m365_channel(c: Ctx) -> dict:
    e, http = c.eng, c.graph
    tid = c.state["team_id"]
    name = m365.channel_name(e.code, _channel_label(c))
    ch, created = m365.ensure_private_channel(
        http, tid, name=name, owner_ids=c.state["owner_ids"],
        description=f"{e.code} {e.name}. {PRACTICE_NAMES[e.practice]} engagement, opened by Vendetta "
                    f"Project Management.")
    if (ch.get("membershipType") or "private") != "private":
        raise ServiceError(f"A {ch.get('membershipType')} channel named '{name}' already exists in the practice "
                           "team. Rename it, or give this kickoff a codename, and retry.")
    c.state.update(channel_id=ch["id"], channel_name=ch.get("displayName") or name,
                   channel_url=ch.get("webUrl") or c.state.get("team_url", ""))
    added = m365.ensure_channel_members(http, tid, ch["id"], owner_ids=c.state["owner_ids"],
                                        member_ids=c.state["member_ids"])
    warn = m365.set_threads_layout(http, tid, ch["id"]) if created else ""
    return {"detail": f"{'Created' if created else 'Found'} private channel {c.state['channel_name']}; "
                      f"{added} person(s) added", "warn": warn, "link": c.state["channel_url"]}


def s_m365_site(c: Ctx) -> dict:
    e, http = c.eng, c.graph
    f = m365.channel_files(http, c.state["team_id"], c.state["channel_id"])
    folders = _names(cfg.folders_ir if e.practice == "ir" else cfg.folders_proserv)
    made = m365.ensure_folders(http, f["drive_id"], f["folder_id"], folders)
    notes = f"{f['folder_name']}/Meeting Notes" if f["folder_name"] else "Meeting Notes"
    if f["site_url"]:
        service.update_engagement(c.db, c.actor, e, sharepoint_site_url=f["site_url"], sharepoint_folder=notes)
    c.state.update(drive_id=f["drive_id"], files_folder_id=f["folder_id"], site_url=f["site_url"],
                   files_url=f["folder_url"] or f["site_url"])
    return {"detail": f"Channel site ready; {len(made)} folder(s) created; meeting notes now save here",
            "link": c.state["files_url"]}


def s_mailbox(c: Ctx) -> dict:
    e, http = c.eng, c.graph
    mailbox = (cfg.ir_mailbox if e.practice == "ir" else cfg.proserv_mailbox).strip().lower()
    address = m365.plus_address(mailbox, m365.nickname(e.code))
    c.state.update(mail_address=address, practice_mailbox=mailbox)
    folder, made_folder = m365.ensure_mail_folder(http, mailbox, m365.channel_name(e.code, _channel_label(c)))
    made_rule = m365.ensure_mail_rule(http, mailbox, name=f"Engagement {e.code}", address=address,
                                      folder_id=folder)
    what = "created" if (made_folder or made_rule) else "already in place"
    return {"detail": f"{address}: mail to it files into its own folder in {mailbox} ({what})"}


def s_teams_tabs(c: Ctx) -> dict:
    e, http = c.eng, c.graph
    team, ch = c.state["team_id"], c.state["channel_id"]
    added, notes = [], []
    if settings.public_url.startswith("https://"):
        url = _public(f"/engagements/{e.id}")
        if m365.ensure_tab(http, team, ch, name="Engagement board", app_id=m365.WEBSITE_TAB_APP, content_url=url):
            added.append("Engagement board")
    else:
        notes.append("engagement board tab needs an https PUBLIC_URL")
    if cfg.vtime_teams_app_id and cfg.vtime_tab_content_url:
        m365.install_app(http, team, cfg.vtime_teams_app_id)
        if m365.ensure_tab(http, team, ch, name="Vendetta Time", app_id=cfg.vtime_teams_app_id,
                           content_url=_vtime_url(team, ch, e.code), entity_id=f"vtime-{m365.nickname(e.code)}"):
            added.append("Vendetta Time")
    else:
        notes.append("Vendetta Time tab needs KICKOFF_VTIME_TEAMS_APP_ID and KICKOFF_VTIME_TAB_CONTENT_URL")
    if not added and notes:
        raise Skip("; ".join(n[0].upper() + n[1:] for n in notes))
    return {"detail": ("Added " + ", ".join(added)) if added else "Tabs already in place",
            "warn": "; ".join(notes)}


def _vtime_url(team: str, channel: str, code: str) -> str:
    return (cfg.vtime_tab_content_url.replace("{teamId}", team).replace("{channelId}", channel)
            .replace("{code}", code))


def s_time_channel(c: Ctx) -> dict:
    """The practice team's Time Entry channel. Its Vendetta Time tab has no
    TabContexts row, so it is not locked to one engagement and asks which one."""
    http, team = c.graph, c.state["team_id"]
    ch, created = m365.ensure_standard_channel(
        http, team, name=cfg.time_channel_name,
        description="Log time against any engagement you are on. Entries go to the engagement manager "
                    "for approval before they post to Harvest.")
    m365.install_app(http, team, cfg.vtime_teams_app_id)
    tab = m365.ensure_tab(http, team, ch["id"], name="Log Time", app_id=cfg.vtime_teams_app_id,
                          content_url=_vtime_url(team, ch["id"], ""), entity_id="vtime-practice")
    if created or tab:
        return {"detail": f"{cfg.time_channel_name} channel ready with the Log Time tab", "link": ch.get("webUrl", "")}
    return {"detail": f"{cfg.time_channel_name} channel already in place", "link": ch.get("webUrl", "")}


def s_vendetta_time(c: Ctx) -> dict:
    e, r, http = c.eng, c.req, c.graph
    site = sharepoint._site_id(http, cfg.vtime_site_url)
    plist, tlist = cfg.vtime_projects_list, cfg.vtime_tabs_list
    row = m365.list_find(http, site, plist, "ProjectCode", e.code)
    hid = c.state.get("harvest_project_id") or e.harvest_project_id or ""
    if row is None:
        pm_id = m365.site_user_lookup_id(http, site, e.pm_email)
        if not pm_id:
            raise ServiceError(f"{e.pm_email} has no entry on the Vendetta Time site yet. Add them to the site's "
                               "PM group (or have them open it once), then retry this step.")
        row = m365.list_add(http, site, plist, {
            "Title": f"{e.code} {e.name}"[:255], "ProjectCode": e.code,
            "Practice": PRACTICE_NAMES[e.practice], "Client": e.client_name or r["client"],
            "ProjectManagerLookupId": pm_id, "Active": True,
            "BillingType": BILLING_TYPE_NAMES[r["billing_type"]], "HarvestProjectId": hid})
        made = "Registered"
    else:
        made = "Already registered"
        if hid and not (row.get("fields") or {}).get("HarvestProjectId"):
            m365.list_update(http, site, plist, row["id"], {"HarvestProjectId": hid})
    pid = str(row["id"])
    c.state["vtime_project_id"] = pid
    detail = f"{made} as Vendetta Time project {pid}"
    if c.state.get("team_id") and c.state.get("channel_id"):
        key = f"channel|{c.state['team_id']}|{c.state['channel_id']}"
        if m365.list_find(http, site, tlist, "ContextKey", key) is None:
            m365.list_add(http, site, tlist, {"Title": f"{e.code} tab", "ContextKey": key, "ProjectId": int(pid)})
        detail += "; the engagement channel's tab is locked to it"
    return {"detail": detail, "link": f"{cfg.vtime_site_url.rstrip('/')}/Lists/{plist}"}


def s_ticket(c: Ctx) -> dict:
    t = ticketing.open_ticket(c.eng, c.req)
    if t:
        c.state.update(ticket_ref=t.get("ref", ""), ticket_url=t.get("url", ""))
        return {"detail": f"Opened ticket {t.get('ref')}", "link": t.get("url", "")}
    if c.req["ticket_ref"]:
        c.state["ticket_ref"] = c.req["ticket_ref"]
        return {"detail": f"Recorded ticket {c.req['ticket_ref']}"}
    raise Skip("No ticketing system is selected yet")


def _client_email_html(c: Ctx) -> tuple[str, str]:
    e, r, st = c.eng, c.req, c.state
    esc = html.escape
    team = [m for m in r["team"] if m["role"] in ("pm", "lead")] or r["team"][:3]
    roles = {"pm": "Project manager", "lead": "Technical lead"}
    rows = "".join(f"<li>{esc(roles.get(m['role'], m['role'].title()))}: {esc(m['email'])}</li>" for m in team)
    mailbox = st.get("mail_address") or ""
    if e.practice == "ir":
        subject = f"{e.code}: incident response kickoff"
        purpose = ("Vendetta Cyber is engaged on this incident. This message confirms the case reference, "
                   "your response team, and how to reach us.")
        ask = ("Please reply with the best times for a kickoff call in the next 24 hours, and confirm who "
               "at your organization (and your breach counsel and insurer, if engaged) should be included.")
    else:
        subject = f"{e.code}: {e.name} kickoff"
        purpose = (f"Thank you for engaging Vendetta Cyber for {esc(e.name)}. This message confirms the "
                   "project reference, your delivery team, and how to reach us.")
        ask = "Please reply with two or three times that work for a kickoff call next week."
    cc = (f"<p>Please copy <b>{esc(mailbox)}</b> on every message about this engagement so the whole team "
          "sees it.</p>") if mailbox else ""
    dates = ""
    if e.starts_on:
        dates = f"<p>Planned start: {e.starts_on:%B %-d, %Y}" + (
            f". Planned completion: {e.ends_on:%B %-d, %Y}." if e.ends_on else ".") + "</p>"
    body = (f"<p>Hello,</p><p>{purpose}</p><p>Reference: <b>{esc(e.code)}</b><br>Engagement: {esc(e.name)}</p>"
            f"<p>Your Vendetta team:</p><ul>{rows}</ul>{cc}{dates}<p>{ask}</p><p>Thank you,</p>")
    return subject, body


def s_client_email(c: Ctx) -> dict:
    e = c.eng
    subject, body = _client_email_html(c)
    m = m365.draft_mail(c.graph, e.pm_email, subject=subject, html=body, to=c.req["client_contacts"],
                        cc=[c.state.get("mail_address", "")])
    return {"detail": f"Draft saved in {e.pm_email}'s Drafts; review and send", "link": m.get("webLink", "")}


def s_announce(c: Ctx) -> dict:
    e, r, st = c.eng, c.req, c.state
    facts = [{"title": "Client", "value": e.client_name or r["client"]},
             {"title": "Practice", "value": PRACTICE_NAMES[e.practice]},
             {"title": "PM", "value": e.pm_email}]
    if e.lead_email:
        facts.append({"title": "Lead", "value": e.lead_email})
    team = ", ".join(m["email"] for m in r["team"] if m["role"] not in ("pm", "lead"))
    if team:
        facts.append({"title": "Team", "value": team})
    if e.budget_hours:
        facts.append({"title": "Budget", "value": f"{e.budget_hours:g} hours, {BILLING_TYPE_NAMES[r['billing_type']]}"})
    if e.platform_ref:
        facts.append({"title": "Platform", "value": e.platform_ref})
    if st.get("channel_name"):
        facts.append({"title": "Channel", "value": f"{st['channel_name']} in {st.get('team_name') or 'the practice team'}"})
    if st.get("mail_address"):
        facts.append({"title": "Email", "value": st["mail_address"]})
    actions = []
    if settings.public_url:
        actions.append({"type": "Action.OpenUrl", "title": "Engagement", "url": _public(f"/engagements/{e.id}")})
    for key, title in (("channel_url", "Channel"), ("files_url", "Files"), ("ticket_url", "Ticket")):
        if st.get(key):
            actions.append({"type": "Action.OpenUrl", "title": title, "url": st[key]})
    card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
        "body": [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                  "text": f"Kickoff: {e.code} {e.name}"},
                 {"type": "FactSet", "facts": facts}],
        "actions": actions}}]}
    with httpx.Client(timeout=20, transport=alerts_mod.TRANSPORT) as http:
        http.post(alerts_mod.cfg.teams_webhook_url, json=card).raise_for_status()
    return {"detail": "Posted to the delivery channel"}


STEP_FNS = {"engagement": s_engagement, "platform": s_platform, "harvest_client": s_harvest_client,
            "harvest_project": s_harvest_project, "harvest_tasks": s_harvest_tasks, "harvest_team": s_harvest_team,
            "m365_team": s_m365_team, "m365_channel": s_m365_channel, "m365_site": s_m365_site,
            "mailbox": s_mailbox, "teams_tabs": s_teams_tabs, "time_channel": s_time_channel,
            "vendetta_time": s_vendetta_time,
            "ticket": s_ticket, "client_email": s_client_email, "announce": s_announce}


# ---------------------------------------------------------------- background
def due(db: Session) -> list[str]:
    return list(db.execute(select(Kickoff.id).where(Kickoff.status.in_(("waiting", "running")),
                                                    Kickoff.next_run_at <= utcnow())).scalars())


def start_loop() -> None:
    if cfg.retry_seconds <= 0:
        return

    def _loop():
        time.sleep(20)
        while True:
            db = SessionLocal()
            try:
                ids = due(db)
            except Exception as e:  # noqa: BLE001
                log.warning("kickoff loop: %s", e)
                ids = []
            finally:
                db.close()
            for kid in ids:
                try:
                    run(kid)
                except Exception as e:  # noqa: BLE001
                    log.warning("kickoff %s: %s", kid, e)
            time.sleep(cfg.retry_seconds)

    threading.Thread(target=_loop, name="kickoff-retry", daemon=True).start()


def readiness() -> dict:
    st = integrations.status()
    return {"harvest": st["harvest"], "graph": st["graph"], "vendetta_time": bool(cfg.vtime_site_url),
            "ir_team": bool(cfg.ir_team_id), "proserv_team": bool(cfg.proserv_team_id),
            "ir_mailbox": bool(cfg.ir_mailbox), "proserv_mailbox": bool(cfg.proserv_mailbox),
            "vendetta_time_tab": bool(cfg.vtime_teams_app_id and cfg.vtime_tab_content_url),
            "ir_hub": bool(settings.platform_hub_url), "announce": bool(alerts_mod.cfg.teams_webhook_url),
            "ticketing": ticketing.provider(), "public_url": settings.public_url.startswith("https://")}
