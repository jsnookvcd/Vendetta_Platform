"""Engagement kickoff: one request opens an IR case or a Professional Services
engagement everywhere it lives, and links every system to every other.

    platform_record   IR hub case (gives the firm-wide case number) or OSP engagement
    engagement        the delivery engagement here: practice card, task board, template
    harvest           Harvest project with the practice's tasks and the team assigned
    m365_workspace    private Microsoft 365 group, Team with threads channels and tags,
                      SharePoint folder tree
    mailbox           Exchange settings for the engagement mailbox (host worker)
    client_uploads    Client Uploads shared to named client contacts, sign-in required
    client_tools      selected client toolset copied into Client Uploads
    superops          SuperOps ticket against the client's account
    slack_channel     optional Slack channel with Slack Connect for the client
    announce          kickoff notice to the delivery channel in Teams and Slack

A run is stored with its steps and every external reference a step created, so a
retry skips finished work and never creates anything twice. Steps that need a
setting that is not configured are recorded as skipped with the reason, and the
result tells Claude which of them it can finish through its own connectors.

The quick steps (platform record, engagement) run in the request so the caller gets
the engagement code at once. The rest run in a background thread; kickoff_status
reads progress.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from . import harvest, m365, milestones as milestones_mod, service, slack, superops
from .config import PRACTICE_NAMES, alert_settings, settings
from .db import Engagement, KickoffRun, MailboxJob, SessionLocal, utcnow
from .service import ServiceError

log = logging.getLogger(__name__)
TRANSPORT: httpx.BaseTransport | None = None  # platform calls; tests swap a MockTransport in
BACKGROUND = True  # tests set False to run every step inline

STEP_NAMES = {
    "platform_record": "Platform record (IR hub case or OSP engagement)",
    "engagement": "Delivery engagement and boards",
    "harvest": "Harvest project",
    "m365_workspace": "Teams, channels, tags and SharePoint",
    "mailbox": "Engagement mailbox settings",
    "client_uploads": "Client Uploads shared to client contacts",
    "client_tools": "Client toolset",
    "superops": "SuperOps ticket",
    "slack_channel": "Slack engagement channel",
    "announce": "Kickoff announcement",
}
ORDER = {
    "ir": ["platform_record", "engagement", "harvest", "superops", "m365_workspace", "mailbox", "client_uploads",
           "client_tools", "slack_channel", "announce"],
    "proserv": ["engagement", "platform_record", "harvest", "superops", "m365_workspace", "mailbox",
                "client_uploads", "client_tools", "slack_channel", "announce"],
}
SYNC_STEPS = {"platform_record", "engagement"}
DEPENDS = {"harvest": "engagement", "superops": "engagement", "m365_workspace": "engagement",
           "mailbox": "m365_workspace", "client_uploads": "m365_workspace", "client_tools": "m365_workspace",
           "slack_channel": "engagement", "announce": "engagement"}
DONE = {"ok", "skipped", "waiting"}
SLACK_MODES = {"none", "announce", "channel"}
IR_TEMPLATES = {"bec", "ransomware", "malware-analysis", "ir-general"}
OSP_KIND = {"tabletop": "tabletop", "vciso-onboarding": "vciso", "pentest": "assessment",
            "pre-ransomware": "assessment"}


# ---------------------------------------------------------------- the request
def _emails(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        v = v.replace(";", ",").split(",")
    return [str(e).strip().lower() for e in v if str(e).strip()]


def normalize(actor: str, raw: dict) -> dict:
    practice = str(raw.get("practice") or "").strip().lower()
    practice = {"ps": "proserv", "professional services": "proserv", "osp": "proserv",
                "incident response": "ir"}.get(practice, practice)
    if practice not in ("ir", "proserv"):
        raise ServiceError("practice must be ir or proserv")
    client = str(raw.get("client") or "").strip()
    if not client:
        raise ServiceError("Name the client")
    etype = str(raw.get("engagement_type") or "").strip().lower() or ("ir-general" if practice == "ir" else "")
    name = str(raw.get("name") or "").strip() or (
        f"{client} {etype.replace('-', ' ').title()}" if etype else f"{client} engagement")
    slack_mode = str(raw.get("slack") or ("announce" if settings.slack_announce_channel else "none")).lower()
    if slack_mode not in SLACK_MODES:
        raise ServiceError("slack must be none, announce or channel")
    pm = _emails(raw.get("pm") or actor)[0]
    lead = (_emails(raw.get("lead")) or [pm])[0]
    team = []
    for m in raw.get("team") or []:
        if isinstance(m, str):
            m = {"email": m}
        e = (_emails(m.get("email")) or [""])[0]
        if e:
            team.append({"email": e, "tags": [str(t).strip() for t in (m.get("tags") or []) if str(t).strip()]})
    known = {m["email"] for m in team}
    for e in [pm, lead] + _emails(settings.kickoff_core_team):
        if e not in known:
            team.append({"email": e, "tags": []})
            known.add(e)
    tools = [str(t).strip() for t in (raw.get("client_tools") or []) if str(t).strip()]
    offered = m365.tool_library()
    bad = [t for t in tools if offered and t not in offered]
    if bad:
        raise ServiceError(f"Unknown client tool(s): {', '.join(bad)}. Offered: {', '.join(offered)}")
    return {
        "practice": practice, "client": client, "name": name, "engagement_type": etype,
        "codename": str(raw.get("codename") or "").strip(), "summary": str(raw.get("summary") or "").strip(),
        "severity": str(raw.get("severity") or "high").lower(),
        "incident_type": str(raw.get("incident_type") or etype or "").strip(),
        "pm": pm, "lead": lead, "team": team, "client_contacts": _emails(raw.get("client_contacts")),
        "requester": (_emails(raw.get("requester")) or _emails(raw.get("client_contacts")) or [""])[0],
        "budget_hours": raw.get("budget_hours"), "fixed_fee": raw.get("fixed_fee"),
        "starts_on": str(service.parse_date(raw.get("starts_on")) or dt.date.today()),
        "ends_on": str(service.parse_date(raw.get("ends_on")) or "") or None,
        "channels": [str(c).strip() for c in (raw.get("channels") or []) if str(c).strip()] or None,
        "extra_channels": [str(c).strip() for c in (raw.get("extra_channels") or []) if str(c).strip()],
        "client_tools": tools, "slack": slack_mode, "superops": bool(raw.get("superops", True)),
        "page_oncall": bool(raw.get("page_oncall", False)), "code": str(raw.get("code") or "").strip(),
        "platform_client_id": str(raw.get("platform_client_id") or "").strip(),
    }


# ---------------------------------------------------------------- runs
def start(db: Session, actor: str, raw: dict) -> KickoffRun:
    spec = normalize(actor, raw)
    run = KickoffRun(practice=spec["practice"], spec=spec, created_by=actor, refs={},
                     steps=[{"key": k, "name": STEP_NAMES[k], "status": "pending", "detail": ""}
                            for k in ORDER[spec["practice"]]])
    db.add(run)
    db.flush()
    for key in ORDER[spec["practice"]]:
        if key in SYNC_STEPS:
            _run_step(db, run, key)
    eng_step = _step(run, "engagement")
    if eng_step["status"] != "ok":
        run.status = "failed"
        _touch(run)
        return run
    db.commit()
    if BACKGROUND:
        threading.Thread(target=_continue, args=(run.id,), name=f"kickoff-{run.code}", daemon=True).start()
    else:
        continue_run(db, run)
    return run


def _continue(run_id: str) -> None:
    db = SessionLocal()
    try:
        run = db.get(KickoffRun, run_id)
        if run is not None:
            continue_run(db, run)
    except Exception:  # noqa: BLE001
        log.exception("kickoff %s failed in the background", run_id)
    finally:
        db.close()


def continue_run(db: Session, run: KickoffRun, only: list[str] | None = None) -> KickoffRun:
    """Run the pending steps in order (or only the named ones)."""
    for key in ORDER[run.practice]:
        if only is not None:
            if key not in only:
                continue
        elif _step(run, key)["status"] != "pending":
            continue
        _run_step(db, run, key)
        db.commit()
    _finish(run)
    db.commit()
    return run


def retry(db: Session, run: KickoffRun, steps: list[str] | None = None) -> KickoffRun:
    """Run failed and skipped steps again (or the named ones). Finished work is
    never repeated: each step reads the refs it stored."""
    todo = steps or [s["key"] for s in run.steps if s["status"] in ("failed", "skipped", "blocked", "pending")]
    unknown = [s for s in todo if s not in STEP_NAMES]
    if unknown:
        raise ServiceError(f"Unknown step(s): {', '.join(unknown)}")
    for key in list(todo):
        for s in run.steps:  # anything that was waiting on a retried step runs again too
            if s["status"] == "blocked" and _depends(run.practice, s["key"]) in todo and s["key"] not in todo:
                todo.append(s["key"])
    for key in todo:
        _step(run, key)["status"] = "pending"
    _flag(run)
    return continue_run(db, run, only=todo)


def find(db: Session, ref: str) -> KickoffRun:
    ref = (ref or "").strip()
    run = db.get(KickoffRun, ref) if ref else None
    if run is None and ref:
        run = db.execute(select(KickoffRun).where(KickoffRun.code == ref)
                         .order_by(KickoffRun.created_at.desc())).scalars().first()
    if run is None and ref:
        try:
            eng = service.find_engagement(db, ref)
            run = db.execute(select(KickoffRun).where(KickoffRun.engagement_id == eng.id)
                             .order_by(KickoffRun.created_at.desc())).scalars().first()
        except ServiceError:
            run = None
    if run is None:
        raise ServiceError(f"No kickoff matches '{ref}'", 404)
    return run


def _step(run: KickoffRun, key: str) -> dict:
    for s in run.steps:
        if s["key"] == key:
            return s
    raise ServiceError(f"Step {key} is not part of this kickoff")


def _flag(run: KickoffRun) -> None:
    """Steps and refs are mutated in place (steps hold on to the refs dict), so mark
    the JSON columns changed for SQLAlchemy to write them."""
    flag_modified(run, "steps")
    flag_modified(run, "refs")


def _touch(run: KickoffRun) -> None:
    _flag(run)
    run.updated_at = utcnow()


def _set(run: KickoffRun, key: str, status: str, detail: str = "") -> None:
    s = _step(run, key)
    s.update(status=status, detail=detail[:600], at=utcnow().isoformat())
    _touch(run)


def _finish(run: KickoffRun) -> None:
    states = {s["status"] for s in run.steps}
    if "failed" in states or "blocked" in states:
        run.status = "partial"
    elif "running" in states or "pending" in states:
        run.status = "running"
    elif "waiting" in states:
        run.status = "waiting"
    else:
        run.status = "complete"
    _touch(run)


def _engagement(db: Session, run: KickoffRun) -> Engagement | None:
    return db.get(Engagement, run.engagement_id) if run.engagement_id else None


def _depends(practice: str, key: str) -> str | None:
    if key == "engagement" and practice == "ir":
        return "platform_record"
    if key == "platform_record" and practice == "proserv":
        return "engagement"
    return DEPENDS.get(key)


def _run_step(db: Session, run: KickoffRun, key: str) -> None:
    dep = _depends(run.practice, key)
    if dep and _step(run, dep)["status"] not in ("ok", "skipped", "waiting"):
        _set(run, key, "blocked", f"waits on: {STEP_NAMES[dep]}")
        return
    _set(run, key, "running")
    db.commit()
    try:
        status, detail = STEPS[key](db, run)
    except (ServiceError, harvest.HarvestError, m365.GraphError, slack.SlackError, superops.SuperOpsError,
            PlatformError) as e:
        db.rollback()
        status, detail = "failed", str(getattr(e, "message", None) or e)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        log.exception("kickoff step %s failed", key)
        status, detail = "failed", f"{type(e).__name__}: {e}"[:400]
    _set(run, key, status, detail)


# ---------------------------------------------------------------- platform
class PlatformError(Exception):
    pass


def _platform(url: str, token: str, body: dict) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(timeout=20.0, transport=TRANSPORT, headers=headers) as http:
            r = http.post(url, json=body)
    except httpx.HTTPError as e:
        raise PlatformError(f"platform unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise PlatformError("the platform rejected this module's token")
    if r.status_code >= 400:
        raise PlatformError(f"platform HTTP {r.status_code}")
    return r.json()


def step_platform_record(db: Session, run: KickoffRun) -> tuple[str, str]:
    spec, refs = run.spec, run.refs
    if refs.get("platform_ref"):
        return "ok", refs["platform_ref"]
    if spec["practice"] == "ir":
        if spec["code"]:
            refs["platform_ref"] = spec["code"]
            return "ok", f"using existing case {spec['code']}"
        if not settings.platform_hub_url:
            return "skipped", "IR hub not configured (PLATFORM_HUB_URL); the case number comes from this module"
        title = spec["summary"] or spec["name"]
        out = _platform(f"{settings.platform_hub_url.rstrip('/')}/api/ir-cases/open", settings.platform_hub_token,
                        {"client": spec["client"], "platform_client_id": spec["platform_client_id"], "title": title,
                         "severity": spec["severity"], "incident_type": spec["incident_type"], "lead": spec["lead"],
                         "source_module": "project-management", "page": spec["page_oncall"]})
        refs["platform_ref"] = out["case_id"]
        return "ok", f"IR hub case {out['case_id']}" + (" (already open)" if out.get("existing") else "")
    eng = _engagement(db, run)
    if not settings.osp_url:
        return "skipped", "Office of Special Projects not configured (OSP_URL)"
    out = _platform(f"{settings.osp_url.rstrip('/')}/api/engagements", settings.osp_token,
                    {"client": spec["client"], "platform_client_id": spec["platform_client_id"], "name": spec["name"],
                     "kind": OSP_KIND.get(spec["engagement_type"], "advisory"), "scope": spec["summary"],
                     "lead": spec["lead"], "starts_on": spec["starts_on"], "ends_on": spec["ends_on"] or ""})
    refs["platform_ref"] = out["id"]
    if eng is not None:
        eng.platform_ref = out["id"]
        milestones_mod.publish(db, eng)
    return "ok", f"OSP engagement {out['id']}"


def step_engagement(db: Session, run: KickoffRun) -> tuple[str, str]:
    spec, refs = run.spec, run.refs
    if run.engagement_id:
        return "ok", run.code
    code = spec["code"] or (refs.get("platform_ref") if spec["practice"] == "ir" else "") or None
    if code:
        existing = db.execute(select(Engagement).where(Engagement.code == code)).scalar_one_or_none()
        if existing:
            run.engagement_id, run.code = existing.id, existing.code
            return "ok", f"{existing.code} already open here; linked"
    template = spec["engagement_type"] or None
    eng = service.create_engagement(
        db, run.created_by, practice=spec["practice"], name=spec["name"], code=code, client=spec["client"],
        pm_email=spec["pm"], lead_email=spec["lead"], description=spec["summary"],
        budget_hours=spec["budget_hours"], starts_on=spec["starts_on"], ends_on=spec["ends_on"],
        platform_ref=refs.get("platform_ref", "") if spec["practice"] == "ir" else "",
        column="Engaged" if spec["practice"] == "ir" else "Scheduled", template=template)
    run.engagement_id, run.code = eng.id, eng.code
    if eng.platform_ref:
        milestones_mod.publish(db, eng)
    return "ok", f"{eng.code} opened" + (f" from template {template}" if template else "")


def step_harvest(db: Session, run: KickoffRun) -> tuple[str, str]:
    if not harvest.configured():
        return "skipped", "Harvest is not connected (Integrations page)"
    spec, eng = run.spec, _engagement(db, run)
    tasks = (settings.kickoff_harvest_tasks_ir if spec["practice"] == "ir"
             else settings.kickoff_harvest_tasks_proserv).split(",")
    harvest.ensure_project(run.refs, client=spec["client"], name=f"{eng.code} {eng.name}", code=eng.code,
                           budget_hours=eng.budget_hours, starts_on=eng.starts_on, ends_on=eng.ends_on,
                           task_names=tasks, team_emails=[m["email"] for m in spec["team"]],
                           fixed_fee=spec["fixed_fee"])
    eng.harvest_project_id = run.refs["harvest_project_id"]
    eng.harvest_project_name = run.refs.get("harvest_project_name", "")
    note = run.refs.get("harvest_notes") or ""
    return "ok", f"project {run.refs['harvest_project_id']}" + (f"; {note}" if note else "")


def _tag_members(spec: dict, ids: dict[str, str]) -> dict[str, list[str]]:
    tags = {t: [] for t in m365.TAGS[spec["practice"]]}
    for m in spec["team"]:
        for t in m["tags"]:
            tags.setdefault(t, []).append(ids[m["email"]])
    for always in {spec["pm"], spec["lead"]}:
        for t in tags:
            tags[t].append(ids[always])
    return tags


def step_m365_workspace(db: Session, run: KickoffRun) -> tuple[str, str]:
    if not m365.configured():
        return "skipped", "Microsoft Graph credentials are not set, or KICKOFF_M365_ENABLED is off"
    spec, refs, eng = run.spec, run.refs, _engagement(db, run)
    owners = list(dict.fromkeys([spec["pm"], spec["lead"]]))
    members = [m["email"] for m in spec["team"]]
    nick = m365.nickname(eng.code, spec["practice"])
    with m365.Graph() as g:
        ids = m365.user_ids(g, owners + members)
        m365.ensure_group(g, refs, name=m365.display_name(spec["practice"], spec["client"], spec["codename"]),
                          description=f"{eng.code} {eng.name}", mail_nickname=nick, owners=owners, members=members)
        _touch(run); db.commit()
        m365.ensure_team(g, refs)
        _touch(run); db.commit()
        tag_members = _tag_members(spec, ids)
        channels = ([c for c in m365.CHANNELS[spec["practice"]] if c["name"] in spec["channels"]]
                    + [{"name": c} for c in spec["channels"]
                       if c not in {x["name"] for x in m365.CHANNELS[spec["practice"]]}]
                    if spec["channels"] else list(m365.CHANNELS[spec["practice"]]))
        channels += [{"name": c} for c in spec["extra_channels"] if c not in {x["name"] for x in channels}]
        m365.ensure_channels(g, refs, practice=spec["practice"], channels=channels,
                             owner_ids=[ids[o] for o in owners], tag_members=tag_members)
        m365.ensure_tags(g, refs, tag_members)
        m365.ensure_site(g, refs)
        m365.ensure_folders(g, refs, spec["practice"])
    eng.sharepoint_site_url = refs.get("site_url", "")
    eng.sharepoint_folder = ""
    note = refs.get("layout_note", "")
    return "ok", f"{refs.get('mailbox')} with {len(refs.get('channels', {}))} channels" + (f"; {note}" if note else "")


def step_mailbox(db: Session, run: KickoffRun) -> tuple[str, str]:
    refs = run.refs
    if _step(run, "m365_workspace")["status"] == "skipped":
        return "skipped", "no Microsoft 365 workspace"
    job = db.execute(select(MailboxJob).where(MailboxJob.run_id == run.id)).scalars().first()
    if job and job.status == "done":
        return "ok", job.detail or "mailbox configured"
    if job is None:
        db.add(MailboxJob(run_id=run.id, group_id=refs["group_id"], address=refs.get("mailbox", ""),
                          members=[m["email"] for m in run.spec["team"]]))
    elif job.status == "failed":
        job.status, job.detail = "pending", ""
    return "waiting", "queued for the mailbox worker: accept external senders, Send As for the team"


def step_client_uploads(db: Session, run: KickoffRun) -> tuple[str, str]:
    contacts = run.spec["client_contacts"]
    if _step(run, "m365_workspace")["status"] == "skipped":
        return "skipped", "no Microsoft 365 workspace"
    if not contacts:
        return "skipped", "no client contacts given; share Client Uploads later with retry_kickoff"
    eng = _engagement(db, run)
    msg = (f"Vendetta has opened {eng.code} for {run.spec['client']}. Use this folder to send us files and "
           f"evidence. Sign in with this email address to open it.")
    with m365.Graph() as g:
        m365.share_uploads(g, run.refs, contacts, msg)
    return "ok", f"shared with {', '.join(run.refs.get('uploads_shared_with', []))}"


def step_client_tools(db: Session, run: KickoffRun) -> tuple[str, str]:
    tools = run.spec["client_tools"]
    if not tools:
        return "skipped", "no client tools selected"
    if _step(run, "m365_workspace")["status"] == "skipped":
        return "skipped", "no Microsoft 365 workspace"
    with m365.Graph() as g:
        m365.copy_client_tools(g, run.refs, tools)
    return "ok", f"copied {', '.join(tools)} to Client Uploads/Vendetta Tools"


def step_superops(db: Session, run: KickoffRun) -> tuple[str, str]:
    spec, eng = run.spec, _engagement(db, run)
    if not spec["superops"]:
        return "skipped", "not requested"
    if run.refs.get("superops_ticket"):
        return "ok", f"ticket {run.refs['superops_ticket']}"
    if not superops.configured():
        return "skipped", "SUPEROPS_API_TOKEN not set; Claude opens the ticket through the SuperOps connector"
    superops.ensure_ticket(run.refs, client=spec["client"], subject=f"{eng.code} {eng.name}",
                           description=_ticket_body(run, eng), practice=spec["practice"],
                           requester=spec["requester"],
                           priority="Critical" if spec["severity"] == "critical" else "High")
    return "ok", f"ticket {run.refs['superops_ticket']} for {run.refs.get('superops_client')}"


def _ticket_body(run: KickoffRun, eng: Engagement) -> str:
    s = run.spec
    return "\n".join(filter(None, [
        f"{PRACTICE_NAMES[s['practice']]} engagement {eng.code}: {eng.name}", s["summary"],
        f"PM: {s['pm']}  Lead: {s['lead']}",
        f"Budget: {eng.budget_hours} hours" if eng.budget_hours else "",
        f"Engagement mailbox: {run.refs.get('mailbox')}" if run.refs.get("mailbox") else ""]))


def step_slack_channel(db: Session, run: KickoffRun) -> tuple[str, str]:
    spec, eng = run.spec, _engagement(db, run)
    if spec["slack"] != "channel":
        return "skipped", "no Slack channel requested"
    if not slack.configured():
        return "skipped", "SLACK_BOT_TOKEN not set"
    slack.ensure_channel(run.refs, code=eng.code, client=spec["client"], purpose=f"{eng.code} {eng.name}",
                         staff=[m["email"] for m in spec["team"]], client_contacts=spec["client_contacts"])
    missing = run.refs.get("slack_not_found") or []
    return "ok", run.refs["slack_channel"] + (f"; not in Slack: {', '.join(missing)}" if missing else "")


def step_announce(db: Session, run: KickoffRun) -> tuple[str, str]:
    eng = _engagement(db, run)
    text = announcement(run, eng)
    sent = []
    if alert_settings.teams_webhook_url:
        card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": [
                                {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                                 "text": f"New {PRACTICE_NAMES[eng.practice]} engagement: {eng.code}"},
                                {"type": "TextBlock", "wrap": True, "text": text}]}}]}
        with httpx.Client(timeout=20.0, transport=TRANSPORT) as http:
            http.post(alert_settings.teams_webhook_url, json=card).raise_for_status()
        sent.append("Teams")
    if run.spec["slack"] in ("announce", "channel") and slack.configured() and settings.slack_announce_channel:
        run.refs["slack_announce_ts"] = slack.announce(text)
        sent.append("Slack")
    if not sent:
        return "skipped", "no delivery channel webhook (ALERT_TEAMS_WEBHOOK_URL) or Slack announce channel set"
    return "ok", "posted to " + " and ".join(sent)


def announcement(run: KickoffRun, eng: Engagement) -> str:
    r, s = run.refs, run.spec
    lines = [f"{eng.code} {eng.name} for {s['client']}.", f"PM {s['pm']}, lead {s['lead']}."]
    if r.get("mailbox"):
        lines.append(f"Engagement mailbox {r['mailbox']}; CC it on every client thread.")
    if r.get("team_url"):
        lines.append(f"Team: {r['team_url']}")
    if r.get("site_url"):
        lines.append(f"SharePoint: {r['site_url']}")
    if r.get("harvest_project_id"):
        lines.append(f"Harvest project {r['harvest_project_id']}.")
    if r.get("superops_ticket"):
        lines.append(f"SuperOps ticket {r['superops_ticket']}.")
    if settings.public_url:
        lines.append(f"Board: {settings.public_url.rstrip('/')}/engagements/{eng.id}")
    return "\n".join(lines)


STEPS = {
    "platform_record": step_platform_record, "engagement": step_engagement, "harvest": step_harvest,
    "m365_workspace": step_m365_workspace, "mailbox": step_mailbox, "client_uploads": step_client_uploads,
    "client_tools": step_client_tools, "superops": step_superops, "slack_channel": step_slack_channel,
    "announce": step_announce,
}


# ---------------------------------------------------------------- mailbox worker
def claim_mailbox_jobs(db: Session, limit: int = 10) -> list[dict]:
    jobs = db.execute(select(MailboxJob).where(MailboxJob.status == "pending").order_by(MailboxJob.created_at)
                      .limit(limit).with_for_update(skip_locked=True)).scalars().all()
    out = []
    for j in jobs:
        j.status, j.attempts, j.updated_at = "claimed", j.attempts + 1, utcnow()
        out.append({"id": j.id, "group_id": j.group_id, "address": j.address, "members": j.members})
    db.commit()
    return out


def report_mailbox_job(db: Session, job_id: str, status: str, detail: str = "") -> dict:
    j = db.get(MailboxJob, job_id)
    if j is None:
        raise ServiceError("No such mailbox job", 404)
    if status not in ("done", "failed"):
        raise ServiceError("status must be done or failed")
    j.status, j.detail, j.updated_at = status, (detail or "")[:800], utcnow()
    run = db.get(KickoffRun, j.run_id)
    if run is not None:
        _set(run, "mailbox", "ok" if status == "done" else "failed",
             detail or ("mailbox configured" if status == "done" else "the mailbox worker reported a failure"))
        _finish(run)
    db.commit()
    return {"ok": True, "job": j.id, "status": j.status}


# ---------------------------------------------------------------- output
FOLLOW_UPS = {
    "superops": "Open the SuperOps ticket with the SuperOps connector, then call record_kickoff_link "
                "with system superops.",
    "slack_channel": "If the client works in Slack, create the channel with the Slack connector, then "
                     "record_kickoff_link with system slack.",
    "m365_workspace": "Microsoft 365 provisioning is not configured here; create the Teams chat and "
                      "SharePoint folder with the Microsoft 365 connector and record_kickoff_link them.",
}


def run_dict(db: Session, run: KickoffRun) -> dict:
    eng = _engagement(db, run)
    r = run.refs or {}
    links = {k: v for k, v in {
        "engagement": f"{settings.public_url.rstrip('/')}/engagements/{eng.id}" if (eng and settings.public_url) else None,
        "platform_ref": r.get("platform_ref"), "mailbox": r.get("mailbox"), "team": r.get("team_url"),
        "team_id": r.get("team_id"), "sharepoint_site": r.get("site_url"), "client_uploads": r.get("uploads_url"),
        "harvest_project_id": r.get("harvest_project_id"), "superops_ticket": r.get("superops_ticket"),
        "slack_channel": r.get("slack_channel"), "channels": r.get("channels"),
    }.items() if v}
    links.update({k: v for k, v in (r.get("external") or {}).items()})
    follow = [FOLLOW_UPS[s["key"]] for s in run.steps
              if s["key"] in FOLLOW_UPS and s["status"] == "skipped" and "not requested" not in s["detail"]
              and "no Slack channel requested" not in s["detail"]]
    return {"kickoff_id": run.id, "code": run.code, "practice": run.practice, "status": run.status,
            "client": run.spec.get("client"), "name": run.spec.get("name"),
            "steps": [{"step": s["key"], "name": s["name"], "status": s["status"], "detail": s.get("detail", "")}
                      for s in run.steps],
            "links": links, "follow_ups_for_claude": follow,
            "team": [m["email"] for m in run.spec.get("team", [])],
            "client_contacts": run.spec.get("client_contacts", []),
            "created_by": run.created_by, "created_at": run.created_at.isoformat() if run.created_at else None}


def record_link(db: Session, run: KickoffRun, system: str, ref: str, url: str = "") -> KickoffRun:
    """Record something Claude created through its own connectors (a SuperOps ticket,
    a Slack channel, a Teams chat) so the run and the engagement carry it."""
    system = (system or "").strip().lower()
    if not system or not ref:
        raise ServiceError("Give the system and the reference")
    ext = dict(run.refs.get("external") or {})
    ext[system] = {"ref": ref, "url": url} if url else ref
    run.refs["external"] = ext
    step_for = {"superops": "superops", "slack": "slack_channel", "teams": "m365_workspace",
                "sharepoint": "m365_workspace"}.get(system)
    if step_for and _step(run, step_for)["status"] in ("skipped", "failed", "blocked"):
        _set(run, step_for, "ok", f"{system} {ref} (created through Claude)")
    if system == "superops":
        run.refs["superops_ticket"] = ref
    if system == "sharepoint" and url:
        eng = _engagement(db, run)
        if eng is not None:
            eng.sharepoint_site_url = url
    _finish(run)
    return run
