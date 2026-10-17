"""The responder: slash commands, buttons, modals, shortcuts and events, all
turned into calls on the IR hub and SABINE on behalf of the person in Slack.

Three entry points, shared by Socket Mode and HTTP mode:

- handle_command(form)        a /ir slash command
- handle_interaction(payload) a button, an overflow menu, a modal submit, a shortcut
- handle_event(payload)       an Events API callback (reactions, mentions)

Each returns the immediate acknowledgement body (or None) within Slack's three
seconds. Anything that talks to the platform runs through DEFER after the ack and
answers through response_url or the Web API. Tests replace DEFER with an inline
call so a test sees the whole effect before it asserts.

The rule throughout: identity first (identity.resolve), then the grant for what is
being done, then the call, then an audit line. A refusal is audited too.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
from typing import Callable

from sqlalchemy import select

from . import blocks, identity, reach, slack
from .config import settings
from .db import Posted, SessionLocal, WarRoom, audit, utcnow
from .identity import Person, Refused

log = logging.getLogger(__name__)
IR, SABINE = "incident-response", "sabine"
CASE_REF = re.compile(r"^[A-Za-z0-9]+-IR-\d{4}-\d+$", re.IGNORECASE)
MENTION = re.compile(r"<@([UW][A-Z0-9_]+)(?:\|[^>]*)?>")
LINK = re.compile(r"<(https?://[^|>]+)\|([^>]+)>")
BARE_LINK = re.compile(r"<(https?://[^|>]+)>")
CHANNEL_REF = re.compile(r"<#([CG][A-Z0-9]+)(?:\|([^>]*))?>")
CASE_STATUSES = ("open", "contained", "eradicated", "recovered", "closed")
SEVERITIES = ("low", "medium", "high", "critical")
WS_ALIASES = {
    "scoping and containment": ["contain", "containment", "scope", "scoping", "c"],
    "forensics and analysis": ["forensics", "forensic", "analysis", "f"],
    "recovery and restoration": ["recovery", "recover", "restore", "restoration", "r"],
    "notification and legal": ["legal", "notify", "notification", "counsel", "l"],
    "resilience and hardening": ["hardening", "harden", "resilience", "h"],
}
WORKSTREAMS = ["Scoping and Containment", "Forensics and Analysis", "Recovery and Restoration",
               "Notification and Legal", "Resilience and Hardening"]


def _spawn(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="slack-work", daemon=True).start()


DEFER: Callable[[Callable[[], None]], None] = _spawn


# ---------------------------------------------------------------- context and replies
class Ctx:
    """One interaction: who, where, and how to answer."""

    def __init__(self, user: str, channel: str = "", response_url: str = "", trigger_id: str = "",
                 thread_ts: str = ""):
        self.user, self.channel, self.response_url = user, channel, response_url
        self.trigger_id, self.thread_ts = trigger_id, thread_ts

    def reply(self, text: str, blocks_: list | None = None, *, public: bool = False) -> None:
        """Ephemeral to the person by default; public posts into the channel so the
        whole war room sees what changed."""
        if public and self.channel:
            body = {"channel": self.channel, "text": text}
            if blocks_:
                body["blocks"] = blocks_
            if self.thread_ts:
                body["thread_ts"] = self.thread_ts
            if slack.try_call("chat.postMessage", **body) is not None:
                return
        if self.response_url:
            body = {"response_type": "ephemeral", "text": text, "replace_original": False}
            if blocks_:
                body["blocks"] = blocks_
            if slack.respond(self.response_url, body):
                return
        if self.channel:
            body = {"channel": self.channel, "user": self.user, "text": text}
            if blocks_:
                body["blocks"] = blocks_
            if self.thread_ts:
                body["thread_ts"] = self.thread_ts
            if slack.try_call("chat.postEphemeral", **body) is not None:
                return
        # Last resort, a DM: the person must hear back.
        slack.try_call("chat.postMessage", channel=self.user, text=text, **({"blocks": blocks_} if blocks_ else {}))


def _ephemeral(text: str) -> dict:
    return {"response_type": "ephemeral", "text": text}


# ---------------------------------------------------------------- helpers
def plain(db, text: str) -> str:
    """Slack mrkdwn to plain text for the case timeline: mentions become names,
    links keep their target."""
    def _user(m):
        try:
            u = identity.slack_user(db, m.group(1))
            return "@" + (u.name or u.email or m.group(1))
        except Refused:
            return "@" + m.group(1)
    text = MENTION.sub(_user, text or "")
    text = LINK.sub(lambda m: f"{m.group(2)} ({m.group(1)})", text)
    text = BARE_LINK.sub(lambda m: m.group(1), text)
    text = CHANNEL_REF.sub(lambda m: "#" + (m.group(2) or m.group(1)), text)
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").strip()


def workstream(word: str) -> str:
    w = (word or "").strip().lower().rstrip(":")
    for full, aliases in WS_ALIASES.items():
        if w == full or w in aliases:
            return next(x for x in WORKSTREAMS if x.lower() == full)
    return ""


def _split_ws(text: str) -> tuple[str, str]:
    """"forensics: image FS01" -> ("Forensics and Analysis", "image FS01")."""
    m = re.match(r"^\s*([A-Za-z ]{1,30}):\s*(.+)$", text or "", re.S)
    if m and workstream(m.group(1)):
        return workstream(m.group(1)), m.group(2).strip()
    return "", (text or "").strip()


def ir_link(case: dict) -> str:
    if case.get("link"):
        return case["link"]
    base = reach.public_url(IR)
    return f"{base}/cases/{case['id']}" if base and case.get("id") else ""


def room_for_channel(db, channel: str) -> WarRoom | None:
    return db.execute(select(WarRoom).where(WarRoom.channel_id == channel, WarRoom.active.is_(True))
                      .order_by(WarRoom.created_at.desc())).scalars().first()


def room_for_case(db, number: str) -> WarRoom | None:
    return db.execute(select(WarRoom).where(func_upper(WarRoom.case_number) == number.upper(), WarRoom.active.is_(True))
                      .order_by(WarRoom.created_at.desc())).scalars().first()


def func_upper(col):
    from sqlalchemy import func
    return func.upper(col)


def fetch_case(ref: str, person: str = "") -> dict:
    r = reach.get(IR, f"/api/ir-cases/{ref}", person=person)
    if r["ok"] and isinstance(r["data"], dict):
        return r["data"]
    raise Refused(f"I could not load {ref}: {r['detail']}" if r["status"] != 404 else f"There is no case {ref}.")


def _case_ref(db, ctx: Ctx, args: list[str]) -> tuple[str, list[str]]:
    """The case a command is about: an explicit case number first, else the war
    room the command was typed in."""
    if args and CASE_REF.match(args[0]):
        return args[0].upper(), args[1:]
    room = room_for_channel(db, ctx.channel)
    if room:
        return room.case_number, args
    raise Refused(f"Which case? Run this in a war room, or name it: `{settings.slack_command} sitrep VCD-IR-2026-781`.")


def _need(person: Person, module: str = IR) -> None:
    if not person.can_write(module):
        what = "work cases" if module == IR else "ask SABINE or decide her proposals"
        raise Refused(f"Your access lets you read but not {what}. Ask a platform admin for analyst access.")


def topic_for(case: dict) -> str:
    return (f"{case.get('severity', '').upper()} | {case['client']['name']} | {case.get('status')} | "
            f"lead {case.get('lead') or 'unassigned'}")[:250]


def refresh_room(db, room: WarRoom, case: dict) -> None:
    slack.try_call("conversations.setTopic", channel=room.channel_id, topic=topic_for(case))
    if room.card_ts:
        case = {**case, "link": ir_link(case)}
        slack.try_call("chat.update", channel=room.channel_id, ts=room.card_ts, text=f"{case['number']} case card",
                       blocks=blocks.case_card(case, in_room=True))
    room.client = case["client"]["name"]
    db.commit()


def _snapshot(case: dict) -> str:
    return f"{case.get('severity')}|{case.get('status')}|{case.get('lead') or ''}"


# ---------------------------------------------------------------- war rooms
def _room_name(number: str, attempt: int) -> str:
    base = f"{settings.warroom_prefix}-{number}".lower()
    base = re.sub(r"[^a-z0-9_-]+", "-", base).strip("-")[:76]
    return base if attempt == 0 else f"{base}-{attempt + 1}"


def _invite(channel: str, slack_ids: list[str]) -> None:
    for uid in dict.fromkeys(u for u in slack_ids if u):
        res = slack.try_call("conversations.invite", channel=channel, users=uid)
        if res is None:
            log.info("invite %s to %s did not go through", uid, channel)


def _standing_invites() -> list[str]:
    out = []
    for item in (settings.warroom_invite or "").split(","):
        item = item.strip()
        if not item:
            continue
        out.append(identity.lookup_by_email(item) if "@" in item else item)
    return out


def open_war_room(db, case: dict, person: Person, *, origin_channel: str = "") -> WarRoom:
    existing = room_for_case(db, case["number"])
    if existing:
        _invite(existing.channel_id, [person.slack_id])
        return existing
    created = None
    for attempt in range(5):
        try:
            created = slack.call("conversations.create", name=_room_name(case["number"], attempt),
                                 is_private=bool(settings.warroom_private))["channel"]
            break
        except slack.SlackError as e:
            if e.error != "name_taken":
                raise Refused(f"Slack would not create the war room ({e.error}). "
                              "Check the app has the channels:manage and groups:write scopes.") from e
    if created is None:
        raise Refused("Every war room name for this case is taken. Bind an existing channel with "
                      f"`{settings.slack_command} link {case['number']}`.")
    ch = created["id"]
    room = WarRoom(channel_id=ch, channel_name=created.get("name", ""), case_id=case["id"], case_number=case["number"],
                   client=case["client"]["name"], created_by=person.email)
    db.add(room)
    db.commit()
    invites = [person.slack_id] + _standing_invites()
    lead = case.get("lead") or ""
    if "@" in lead:
        invites.append(identity.lookup_by_email(lead))
    _invite(ch, invites)
    slack.try_call("conversations.setTopic", channel=ch, topic=topic_for(case))
    slack.try_call("conversations.setPurpose", channel=ch,
                   purpose=f"War room for {case['number']}. Log to the case timeline with :{settings.memo_reaction}: "
                           f"or {settings.slack_command} note.")
    card = slack.try_call("chat.postMessage", channel=ch, text=f"{case['number']} case card",
                          blocks=blocks.case_card({**case, "link": ir_link(case)}, in_room=True))
    if card:
        room.card_ts = card.get("ts", "")
        slack.try_call("pins.add", channel=ch, timestamp=room.card_ts)
    slack.try_call("chat.postMessage", channel=ch, text=blocks.help_text())
    room_last[room.id] = _snapshot(case)
    db.commit()
    reach.post(IR, f"/api/ir-cases/{case['number']}/updates", person=person.email,
               json_body={"note": f"War room opened in Slack: #{room.channel_name}.", "internal_only": True})
    audit(db, "warroom.open", f"{case['number']} #{room.channel_name} ({ch})", slack_user=person.slack_id, actor=person.email)
    return room


room_last: dict[str, str] = {}  # war room id -> last case snapshot the room was told about


# ---------------------------------------------------------------- the commands
def cmd_help(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    ctx.reply(blocks.help_text())


def cmd_cases(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    r = reach.get(IR, "/api/ir-cases", params={"status": "active"}, person=person.email)
    if not r["ok"]:
        raise Refused(f"The IR hub did not answer: {r['detail']}")
    cases = r["data"] or []
    if not cases:
        ctx.reply("No active cases. Quiet is good.")
        return
    out = [blocks.md(f"*Active cases ({len(cases)})*")]
    for c in cases[:20]:
        room = room_for_case(db, c["number"])
        line = blocks.case_line(c) + (f"  <#{room.channel_id}>" if room else "")
        out.append({"type": "section", "text": {"type": "mrkdwn", "text": line},
                    "accessory": blocks.button("Sitrep", "sitrep", c["number"])})
    if len(cases) > 20:
        out.append(blocks.ctx(f"and {len(cases) - 20} more in the IR hub"))
    ctx.reply(f"{len(cases)} active cases", out)


def cmd_sitrep(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    ref, _ = _case_ref(db, ctx, args)
    case = fetch_case(ref, person.email)
    case["link"] = ir_link(case)
    room = room_for_case(db, case["number"])
    in_room = bool(room and room.channel_id == ctx.channel)
    ctx.reply(f"Sitrep {case['number']}", blocks.sitrep(case, in_room=in_room, room=room.channel_name if room else ""),
              public=in_room)


def cmd_note(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    ws, note = _split_ws(" ".join(rest))
    note = plain(db, note)
    if not note:
        raise Refused(f"What should I log? `{settings.slack_command} note <text>`")
    r = reach.post(IR, f"/api/ir-cases/{ref}/updates", person=person.email,
                   json_body={"note": note, "workstream": ws, "internal_only": True})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.note", f"{ref} {note[:200]}", slack_user=person.slack_id, actor=person.email)
    room = room_for_channel(db, ctx.channel)
    ctx.reply(f":{settings.memo_reaction}: {person.first} logged to {ref}" + (f" ({blocks.WS_SHORT.get(ws, ws)})" if ws else "")
              + f": {blocks.esc(note[:500])}", public=bool(room and room.case_number == ref))


def cmd_status(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    status = (rest[0] if rest else "").lower()
    status = {"close": "closed", "contain": "contained", "eradicate": "eradicated", "recover": "recovered",
              "reopen": "open"}.get(status, status)
    if status not in CASE_STATUSES:
        raise Refused(f"Status is one of {', '.join(CASE_STATUSES)}.")
    r = reach.post(IR, f"/api/ir-cases/{ref}/status", person=person.email, json_body={"status": status})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.status", f"{ref} {r['data'].get('from')}->{status}", slack_user=person.slack_id, actor=person.email)
    _after_change(db, ctx, ref, person, f"{blocks.STATUS_ICON.get(status, '')} {person.first} set {ref} to *{status}*.")


def cmd_sev(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    sev = (rest[0] if rest else "").lower()
    if sev not in SEVERITIES:
        raise Refused(f"Severity is one of {', '.join(SEVERITIES)}.")
    r = reach.post(IR, f"/api/ir-cases/{ref}/details", person=person.email, json_body={"severity": sev})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.severity", f"{ref} {sev}", slack_user=person.slack_id, actor=person.email)
    _after_change(db, ctx, ref, person, f"{blocks.SEV_ICON.get(sev, '')} {person.first} set {ref} severity to *{sev}*.")


def cmd_lead(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    target = " ".join(rest).strip()
    m = MENTION.search(target)
    if target.lower() in ("me", "myself"):
        who_id, who = person.slack_id, person
    elif m:
        who_id = m.group(1)
        try:
            u = identity.slack_user(db, who_id)
        except Refused:
            raise Refused("I could not look that person up in Slack.")
        who = Person(slack_id=who_id, email=u.email, name=u.name, roles={})
    else:
        raise Refused(f"Who leads? `{settings.slack_command} lead @dan` or `{settings.slack_command} lead me`")
    lead = who.name or who.email
    r = reach.post(IR, f"/api/ir-cases/{ref}/details", person=person.email, json_body={"lead": lead})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.lead", f"{ref} {lead}", slack_user=person.slack_id, actor=person.email)
    room = room_for_case(db, ref)
    if room:
        _invite(room.channel_id, [who_id])
    _after_change(db, ctx, ref, person, f":bust_in_silhouette: {person.first} made <@{who_id}> lead on {ref}.")


def cmd_task(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    text = " ".join(rest)
    owner = ""
    mentions = MENTION.findall(text)
    if mentions:
        try:
            u = identity.slack_user(db, mentions[-1])
            owner = u.name or u.email
        except Refused:
            owner = ""
        text = MENTION.sub("", text)
    ws, title = _split_ws(text)
    title = plain(db, title)
    if not title:
        raise Refused(f"What is the card? `{settings.slack_command} task forensics: image FS01 @dan`")
    ws = ws or WORKSTREAMS[0]
    r = reach.post(IR, f"/api/ir-cases/{ref}/tasks", person=person.email,
                   json_body={"workstream": ws, "title": title, "owner": owner})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.task", f"{ref} {ws}: {title[:200]}", slack_user=person.slack_id, actor=person.email)
    room = room_for_channel(db, ctx.channel)
    ctx.reply(f":heavy_plus_sign: {person.first} added a {blocks.WS_SHORT.get(ws, ws)} card on {ref}: {blocks.esc(title)}"
              + (f" ({blocks.esc(owner)})" if owner else ""), public=bool(room and room.case_number == ref))


def cmd_tasks(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    ref, _ = _case_ref(db, ctx, args)
    case = fetch_case(ref, person.email)
    ctx.reply(f"Open cards on {ref}", blocks.task_list(case))


def cmd_page(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    ref, rest = _case_ref(db, ctx, args)
    msg = plain(db, " ".join(rest)) or "Responder needed now."
    case = fetch_case(ref, person.email)
    room = room_for_case(db, ref)
    body = f"{msg}\nPaged from Slack by {person.name or person.email}."
    if room:
        body += f"\nWar room: #{room.channel_name}"
    r = reach.post(IR, "/api/oncall/page", person=person.email, json_body={
        "title": f"{ref} {case['client']['name']}: {msg[:120]}", "body": body, "link": ir_link(case),
        "severity": case.get("severity"), "platform_client_id": case["client"].get("platform_client_id", ""),
        "client": case["client"]["name"], "source_module": "slack", "source_ref": ref})
    if not r["ok"]:
        raise Refused(f"The page did not go out: {r['detail']}")
    sent = ", ".join(sorted((r["data"] or {}).get("sent") or {})) or "no channel configured in the IR hub"
    reach.post(IR, f"/api/ir-cases/{ref}/updates", person=person.email,
               json_body={"note": f"Paged on-call from Slack ({sent}): {msg}", "internal_only": True})
    audit(db, "case.page", f"{ref} sent={sent}", slack_user=person.slack_id, actor=person.email)
    ctx.reply(f":rotating_light: {person.first} paged on-call for {ref} ({sent}).",
              public=bool(room and room.channel_id == ctx.channel))


def cmd_room(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    if not args or not CASE_REF.match(args[0]):
        raise Refused(f"Which case? `{settings.slack_command} room VCD-IR-2026-781`")
    case = fetch_case(args[0].upper(), person.email)
    room = open_war_room(db, case, person)
    ctx.reply(f"War room for {case['number']}: <#{room.channel_id}>")


def cmd_link(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    if not args or not CASE_REF.match(args[0]):
        raise Refused(f"Which case? `{settings.slack_command} link VCD-IR-2026-781`")
    case = fetch_case(args[0].upper(), person.email)
    info = slack.try_call("conversations.info", channel=ctx.channel)
    chan = (info or {}).get("channel") or {}
    if chan and not chan.get("is_member"):
        if chan.get("is_private") or slack.try_call("conversations.join", channel=ctx.channel) is None:
            raise Refused(f"Add me to this channel first (`/invite @SABINE`), then run link again.")
    for old in db.execute(select(WarRoom).where(WarRoom.channel_id == ctx.channel, WarRoom.active.is_(True))).scalars():
        old.active = False
    room = WarRoom(channel_id=ctx.channel, channel_name=chan.get("name", ""), case_id=case["id"],
                   case_number=case["number"], client=case["client"]["name"], created_by=person.email)
    db.add(room)
    db.commit()
    card = slack.try_call("chat.postMessage", channel=ctx.channel, text=f"{case['number']} case card",
                          blocks=blocks.case_card({**case, "link": ir_link(case)}, in_room=True))
    if card:
        room.card_ts = card.get("ts", "")
        slack.try_call("pins.add", channel=ctx.channel, timestamp=room.card_ts)
    room_last[room.id] = _snapshot(case)
    db.commit()
    reach.post(IR, f"/api/ir-cases/{case['number']}/updates", person=person.email,
               json_body={"note": f"Slack channel #{room.channel_name or ctx.channel} bound to this case.", "internal_only": True})
    audit(db, "warroom.link", f"{case['number']} {ctx.channel}", slack_user=person.slack_id, actor=person.email)
    ctx.reply(f":link: {person.first} bound this channel to {case['number']}.", public=True)


def cmd_unlink(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    room = room_for_channel(db, ctx.channel)
    if not room:
        raise Refused("This channel is not bound to a case.")
    room.active = False
    db.commit()
    audit(db, "warroom.unlink", f"{room.case_number} {ctx.channel}", slack_user=person.slack_id, actor=person.email)
    ctx.reply(f"This channel is no longer bound to {room.case_number}. Nothing on the case changed.", public=True)


def cmd_ask(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    question = plain(db, " ".join(args))
    if not question:
        raise Refused("Ask me something.")
    person.roles.setdefault(SABINE, identity.role_for(person.email, SABINE))
    _need(person, SABINE)
    room = room_for_channel(db, ctx.channel)
    if room and not CASE_REF.search(question.split()[0] if question.split() else ""):
        question = f"{question} (asked in the war room for {room.case_number})"
    r = reach.post(SABINE, "/api/ask", person=person.email, json_body={"question": question}, timeout=30.0)
    if not r["ok"]:
        raise Refused(f"SABINE did not answer: {r['detail']}")
    data = r["data"] or {}
    out = [blocks.md(blocks.esc(data.get("reply") or ""))]
    p = data.get("proposal")
    if p and p.get("status") == "pending":
        out += blocks.proposal_card(p, console_url=_sabine_url(p["id"]))
    audit(db, "sabine.ask", question[:300], slack_user=person.slack_id, actor=person.email)
    ctx.reply(data.get("reply") or "SABINE answered.", out)


COMMANDS: dict[str, tuple[Callable, tuple[str, ...]]] = {
    "help": (cmd_help, (IR,)),
    "cases": (cmd_cases, (IR,)),
    "sitrep": (cmd_sitrep, (IR,)),
    "status": (cmd_status, (IR,)),
    "note": (cmd_note, (IR,)),
    "log": (cmd_note, (IR,)),
    "sev": (cmd_sev, (IR,)),
    "severity": (cmd_sev, (IR,)),
    "lead": (cmd_lead, (IR,)),
    "task": (cmd_task, (IR,)),
    "card": (cmd_task, (IR,)),
    "tasks": (cmd_tasks, (IR,)),
    "cards": (cmd_tasks, (IR,)),
    "page": (cmd_page, (IR,)),
    "room": (cmd_room, (IR,)),
    "warroom": (cmd_room, (IR,)),
    "link": (cmd_link, (IR,)),
    "unlink": (cmd_unlink, (IR,)),
    "ask": (cmd_ask, (SABINE, IR)),
}
# Shorthand: "/ir contained" sets the status.
for _s in ("contained", "eradicated", "recovered", "closed"):
    COMMANDS[_s] = (lambda db, ctx, p, a, _s=_s: cmd_status(db, ctx, p, [*a[:1], _s] if a and CASE_REF.match(a[0]) else [_s]), (IR,))


def _after_change(db, ctx: Ctx, ref: str, person: Person, text: str) -> None:
    room = room_for_case(db, ref)
    if room:
        try:
            case = fetch_case(ref, person.email)
            refresh_room(db, room, case)
            room_last[room.id] = _snapshot(case)
        except Refused:
            pass
    ctx.reply(text, public=bool(room and room.channel_id == ctx.channel))
    if room and room.channel_id != ctx.channel:
        slack.try_call("chat.postMessage", channel=room.channel_id, text=text)


def run(ctx: Ctx, sub: str, args: list[str]) -> None:
    """Run one command for ctx.user. Every outcome is answered and audited."""
    db = SessionLocal()
    try:
        fn, modules = COMMANDS.get(sub, (None, (IR,)))
        if fn is None:
            ctx.reply(f"I do not know `{sub}`.\n\n" + blocks.help_text())
            return
        try:
            person = identity.resolve(db, ctx.user, modules)
            if not person.can_read(IR) and fn is not cmd_ask:
                raise Refused("You have no incident-response access on the platform roster.")
            fn(db, ctx, person, args)
        except Refused as e:
            audit(db, f"refused.{sub}", str(e), slack_user=ctx.user, ok=False)
            ctx.reply(str(e))
    except Exception:  # noqa: BLE001
        log.exception("slack command %s failed", sub)
        ctx.reply("Something went wrong on my side. The attempt is in the responder's log.")
    finally:
        db.close()


# ---------------------------------------------------------------- declare
def _ir_clients() -> list[dict]:
    r = reach.get("platform", "/api/platform/clients", params={"module": IR})
    return [{"id": c["id"], "name": c["name"]} for c in ((r["data"] or {}).get("clients") or [])] if r["ok"] else []


def _match_client(clients: list[dict], text: str) -> tuple[dict | None, list[dict]]:
    t = text.strip().lower()
    exact = [c for c in clients if c["name"].lower() == t]
    if exact:
        return exact[0], exact
    hits = [c for c in clients if c["name"].lower().startswith(t) or t in c["name"].lower()]
    return (hits[0] if len(hits) == 1 else None), hits


def declare(db, ctx: Ctx, person: Person, *, client_id: str = "", client_name: str = "", severity: str = "high",
            description: str = "", room: bool = True) -> None:
    _need(person)
    body = {"severity": severity, "description": description or "Incident declared from Slack"}
    if client_id:
        body["platform_client_id"] = client_id
    if client_name:
        body["client"] = client_name
    r = reach.post(IR, "/api/ir-cases/declare", person=person.email, json_body=body)
    if not r["ok"]:
        raise Refused(f"The IR hub did not open the case: {r['detail']}")
    number = r["data"]["case_id"]
    case = fetch_case(number, person.email)
    case["link"] = r["data"].get("link") or ir_link(case)
    audit(db, "case.declare", f"{number} {case['client']['name']} {severity}", slack_user=person.slack_id, actor=person.email)
    warroom = None
    if room:
        try:
            warroom = open_war_room(db, case, person)
        except Refused as e:
            ctx.reply(f"{number} is open but the war room was not: {e}")
    _announce_case(db, case, warroom, declared_by=person)
    where = f" War room: <#{warroom.channel_id}>." if warroom else ""
    ctx.reply(f":rotating_light: {number} is open for {case['client']['name']} ({severity}). On-call has been paged.{where}")


def cmd_declare_text(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    """/ir declare critical Riverbend: ransom note on FS01"""
    _need(person)
    sev = "high"
    if args and args[0].lower() in SEVERITIES:
        sev, args = args[0].lower(), args[1:]
    text = " ".join(args)
    if ":" not in text:
        raise Refused(f"Use `{settings.slack_command} declare` on its own for the form, or "
                      f"`{settings.slack_command} declare critical <client>: <what is happening>`.")
    who, desc = text.split(":", 1)
    clients = _ir_clients()
    match, hits = _match_client(clients, who)
    if match is None:
        if hits:
            raise Refused("More than one client matches: " + ", ".join(c["name"] for c in hits[:8]) + ". Be more specific.")
        raise Refused(f"No client with incident response enabled matches '{who.strip()}'. The form lists them: "
                      f"`{settings.slack_command} declare`.")
    declare(db, ctx, person, client_id=match["id"], client_name=match["name"], severity=sev,
            description=plain(db, desc), room=True)


# ---------------------------------------------------------------- slash command entry
def handle_command(form: dict) -> dict | None:
    if not slack.allowed_team(form.get("team_id", "")):
        return _ephemeral("This responder belongs to another workspace.")
    text = (form.get("text") or "").strip()
    parts = text.split()
    sub = (parts[0].lower() if parts else "help")
    args = parts[1:]
    ctx = Ctx(user=form.get("user_id", ""), channel=form.get("channel_id", ""),
              response_url=form.get("response_url", ""), trigger_id=form.get("trigger_id", ""))
    if sub == "declare" and not args:
        # The modal must open within three seconds of the command, so this one runs now.
        return _open_declare(ctx)
    if sub == "declare":
        DEFER(lambda: _run_fn(ctx, "declare", cmd_declare_text, args))
        return None
    DEFER(lambda: run(ctx, sub, args))
    return None


def _run_fn(ctx: Ctx, label: str, fn, args, modules=(IR,)) -> None:
    db = SessionLocal()
    try:
        try:
            person = identity.resolve(db, ctx.user, modules)
            fn(db, ctx, person, args)
        except Refused as e:
            audit(db, f"refused.{label}", str(e), slack_user=ctx.user, ok=False)
            ctx.reply(str(e))
    except Exception:  # noqa: BLE001
        log.exception("slack %s failed", label)
        ctx.reply("Something went wrong on my side. The attempt is in the responder's log.")
    finally:
        db.close()


def _open_declare(ctx: Ctx, preset: str = "") -> dict | None:
    db = SessionLocal()
    try:
        try:
            person = identity.resolve(db, ctx.user, (IR,))
            _need(person)
        except Refused as e:
            audit(db, "refused.declare", str(e), slack_user=ctx.user, ok=False)
            return _ephemeral(str(e))
        try:
            slack.call("views.open", trigger_id=ctx.trigger_id, view=blocks.declare_modal(_ir_clients(), ctx.channel, preset))
        except slack.SlackError as e:
            return _ephemeral(f"Slack would not open the form ({e.error}). "
                              f"Try `{settings.slack_command} declare critical <client>: <what is happening>`.")
        return None
    finally:
        db.close()


# ---------------------------------------------------------------- interactions
def _val(state: dict, block: str, kind: str = "value"):
    v = (state.get(block) or {}).get("v") or {}
    if kind == "select":
        return ((v.get("selected_option") or {}).get("value")) or ""
    if kind == "checks":
        return [o.get("value") for o in v.get("selected_options") or []]
    return (v.get("value") or "").strip()


def handle_interaction(payload: dict) -> dict | None:
    if not slack.allowed_team((payload.get("team") or {}).get("id", "")):
        return None
    kind = payload.get("type")
    user = (payload.get("user") or {}).get("id", "")
    if kind == "view_submission":
        return _view_submission(payload, user)
    if kind == "shortcut" and payload.get("callback_id") == "declare":
        return _open_declare(Ctx(user=user, trigger_id=payload.get("trigger_id", "")))
    if kind == "message_action" and payload.get("callback_id") == "log_to_case":
        return _message_shortcut(payload, user)
    if kind == "block_actions":
        for a in payload.get("actions") or []:
            _block_action(payload, user, a)
    return None


def _block_action(payload: dict, user: str, action: dict) -> None:
    aid = action.get("action_id", "")
    channel = (payload.get("channel") or {}).get("id", "") or (payload.get("container") or {}).get("channel_id", "")
    ctx = Ctx(user=user, channel=channel, response_url=payload.get("response_url", ""))
    value = action.get("value", "")
    if aid in ("open_ir", "open_sabine"):
        return  # link buttons: Slack opens the URL, nothing to do here
    if aid == "sitrep":
        DEFER(lambda: run(ctx, "sitrep", [value]))
    elif aid == "tasks":
        DEFER(lambda: run(ctx, "tasks", [value]))
    elif aid == "warroom":
        DEFER(lambda: _run_fn(ctx, "warroom", _join_room, [value]))
    elif aid == "task_move":
        sel = (action.get("selected_option") or {}).get("value", "")
        DEFER(lambda: _run_fn(ctx, "task_move", _task_move, [sel]))
    elif aid in ("proposal_approve", "proposal_reject"):
        msg_ts = (payload.get("container") or {}).get("message_ts", "") or (payload.get("message") or {}).get("ts", "")
        DEFER(lambda: _run_fn(ctx, "proposal", _decide, [value, aid == "proposal_approve", msg_ts], modules=(SABINE,)))


def _join_room(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    number = args[0]
    room = room_for_case(db, number)
    if room:
        _invite(room.channel_id, [person.slack_id])
        ctx.reply(f"You are in <#{room.channel_id}>.")
        return
    _need(person)
    case = fetch_case(number, person.email)
    room = open_war_room(db, case, person)
    ctx.reply(f"War room for {number}: <#{room.channel_id}>")


def _task_move(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _need(person)
    try:
        number, tid, status = args[0].split("|")
    except ValueError:
        raise Refused("That card action was malformed.")
    r = reach.post(IR, f"/api/ir-cases/{number}/tasks/{tid}/move", person=person.email, json_body={"status": status})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    audit(db, "case.task_move", f"{number} {tid} {status}", slack_user=person.slack_id, actor=person.email)
    case = fetch_case(number, person.email)
    title = next((t["title"] for t in case.get("tasks") or [] if t["id"] == tid), "card")
    label = {"in_progress": "started", "blocked": "marked blocked", "done": "finished"}.get(status, status)
    room = room_for_case(db, number)
    text = f"{blocks.TASK_ICON.get(status, '')} {person.first} {label}: {blocks.esc(title)} ({number})"
    if room:
        slack.try_call("chat.postMessage", channel=room.channel_id, text=text)
        if room.channel_id != ctx.channel:
            ctx.reply(text)
    else:
        ctx.reply(text)
    if ctx.response_url:
        slack.respond(ctx.response_url, {"replace_original": True, "text": f"Open cards on {number}",
                                         "blocks": blocks.task_list(case)})


def _sabine_url(pid: str) -> str:
    base = reach.public_url(SABINE)
    return f"{base}/proposals/{pid}" if base else ""


def _decide(db, ctx: Ctx, person: Person, args: list) -> None:
    pid, approve, msg_ts = args
    _need(person, SABINE)
    r = reach.post(SABINE, f"/api/proposals/{pid}/decide", person=person.email,
                   json_body={"approve": approve, "note": "Decided in Slack"})
    data = r["data"] or {}
    if r["status"] == 403:
        raise Refused("That one is high risk. It is decided in the SABINE console by someone with the grant.")
    if not r["ok"] and r["status"] != 409:
        raise Refused(f"SABINE did not take the decision: {r['detail']}")
    p = data.get("proposal") or {}
    verb = "approved" if approve else "rejected"
    if r["status"] == 409:
        decided = f"Already {p.get('status') or 'decided'}" + (f" by {p.get('decided_by')}" if p.get("decided_by") else "") + "."
    else:
        res = data.get("result") or p.get("result") or {}
        outcome = ""
        if approve and isinstance(res, dict) and "ok" in res:
            outcome = "  Carried out." if res.get("ok") else f"  It did not go through: {res.get('detail') or 'see SABINE'}."
        decided = f"{':white_check_mark:' if approve else ':x:'} {verb.capitalize()} by {person.name or person.email} in Slack.{outcome}"
    audit(db, f"sabine.{verb}", f"{pid} {decided}", slack_user=person.slack_id, actor=person.email, ok=r["ok"])
    row = db.execute(select(Posted).where(Posted.kind == "proposal", Posted.ref == pid)).scalar_one_or_none()
    channel, ts = (row.channel, row.ts) if row and row.ts else (ctx.channel, msg_ts)
    if row:
        row.state = p.get("status") or verb
        db.commit()
    if channel and ts and p:
        slack.try_call("chat.update", channel=channel, ts=ts, text=decided,
                       blocks=blocks.proposal_card(p, console_url=_sabine_url(pid), decided=decided))
    else:
        ctx.reply(decided)


def _view_submission(payload: dict, user: str) -> dict | None:
    view = payload.get("view") or {}
    state = (view.get("state") or {}).get("values") or {}
    cb = view.get("callback_id")
    if cb == "declare":
        client_id = _val(state, "client", "select")
        client_name = _val(state, "client_name")
        desc = _val(state, "desc")
        if not (client_id or client_name):
            return {"response_action": "errors", "errors": {"client": "Choose the client."}}
        if not desc:
            return {"response_action": "errors", "errors": {"desc": "Say what is happening, even one line."}}
        sev = _val(state, "severity", "select") or "high"
        room = "yes" in _val(state, "room", "checks")
        ctx = Ctx(user=user, channel=view.get("private_metadata", ""))
        DEFER(lambda: _run_fn(ctx, "declare", lambda db, c, p, a: declare(
            db, c, p, client_id=client_id, client_name=client_name, severity=sev, description=desc, room=room), []))
        return None
    if cb == "log_to_case":
        try:
            meta = json.loads(view.get("private_metadata") or "{}")
        except ValueError:
            meta = {}
        number = _val(state, "case", "select")
        note = _val(state, "note")
        if not number or not note:
            return {"response_action": "errors", "errors": {"note": "Nothing to log."}}
        ctx = Ctx(user=user, channel=meta.get("channel", ""))
        DEFER(lambda: _run_fn(ctx, "log", _log_entry, [number, note, meta]))
        return None
    return None


# ---------------------------------------------------------------- logging messages to the timeline
def _message_note(db, msg: dict) -> str:
    author = ""
    if msg.get("user"):
        try:
            u = identity.slack_user(db, msg["user"])
            author = u.name or u.email
        except Refused:
            author = msg["user"]
    elif msg.get("username") or msg.get("bot_profile"):
        author = msg.get("username") or (msg.get("bot_profile") or {}).get("name") or "a bot"
    when = ""
    try:
        when = dt.datetime.fromtimestamp(float(msg.get("ts", "0")), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        pass
    text = plain(db, msg.get("text") or "")
    files = [f.get("name") or f.get("title") or "file" for f in msg.get("files") or []]
    if files:
        text += ("\n" if text else "") + "Attachments in Slack: " + ", ".join(files[:10])
    return f"From Slack, {author or 'unknown'} at {when}:\n{text}".strip()


def _log_entry(db, ctx: Ctx, person: Person, args: list) -> None:
    number, note, meta = args
    _need(person)
    key = f"{meta.get('channel', '')}:{meta.get('ts', '')}:{number}"
    if meta.get("ts") and db.execute(select(Posted).where(Posted.kind == "log", Posted.ref == key[:64])).scalar_one_or_none():
        ctx.reply(f"That message is already on the {number} timeline.")
        return
    permalink = meta.get("permalink") or ""
    r = reach.post(IR, f"/api/ir-cases/{number}/updates", person=person.email,
                   json_body={"note": note, "internal_only": True, "source": permalink})
    if not r["ok"]:
        raise Refused(f"The IR hub did not take that: {r['detail']}")
    if meta.get("ts"):
        db.add(Posted(kind="log", ref=key[:64], channel=meta.get("channel", ""), ts=meta.get("ts", "")))
        db.commit()
        slack.try_call("reactions.add", channel=meta.get("channel"), timestamp=meta.get("ts"), name="white_check_mark")
    audit(db, "case.log_message", f"{number} {permalink}", slack_user=person.slack_id, actor=person.email)
    ctx.reply(f":white_check_mark: Logged to the {number} timeline.")


def _message_shortcut(payload: dict, user: str) -> dict | None:
    channel = (payload.get("channel") or {}).get("id", "")
    msg = payload.get("message") or {}
    ctx = Ctx(user=user, channel=channel, response_url=payload.get("response_url", ""),
              trigger_id=payload.get("trigger_id", ""))
    db = SessionLocal()
    try:
        room = room_for_channel(db, channel)
        meta = {"channel": channel, "ts": msg.get("ts", "")}
        if room:
            def work():
                d = SessionLocal()
                try:
                    link = slack.try_call("chat.getPermalink", channel=channel, message_ts=msg.get("ts", ""))
                    m = {**meta, "permalink": (link or {}).get("permalink", "")}
                    _run_fn(ctx, "log", _log_entry, [room.case_number, _message_note(d, msg), m])
                finally:
                    d.close()
            DEFER(work)
            return None
        # Not a war room: let the person pick the case.
        try:
            person = identity.resolve(db, user, (IR,))
            _need(person)
        except Refused as e:
            ctx.reply(str(e))
            return None
        r = reach.get(IR, "/api/ir-cases", params={"status": "active"}, person=person.email)
        cases = (r["data"] or []) if r["ok"] else []
        if not cases:
            ctx.reply("There are no active cases to log to.")
            return None
        link = slack.try_call("chat.getPermalink", channel=channel, message_ts=msg.get("ts", ""))
        meta["permalink"] = (link or {}).get("permalink", "")
        slack.try_call("views.open", trigger_id=ctx.trigger_id,
                       view=blocks.log_modal(cases, json.dumps(meta), _message_note(db, msg)))
        return None
    finally:
        db.close()


def _fetch_message(channel: str, ts: str) -> dict | None:
    d = slack.try_call("conversations.history", channel=channel, latest=ts, inclusive="true", limit=1)
    for m in (d or {}).get("messages") or []:
        if m.get("ts") == ts:
            return m
    d = slack.try_call("conversations.replies", channel=channel, ts=ts, limit=200)
    for m in (d or {}).get("messages") or []:
        if m.get("ts") == ts:
            return m
    return None


def _reaction(event: dict) -> None:
    item = event.get("item") or {}
    if item.get("type") != "message" or event.get("reaction") != settings.memo_reaction:
        return
    if event.get("user") == slack.IDENTITY.get("bot_user_id"):
        return
    channel, ts, user = item.get("channel", ""), item.get("ts", ""), event.get("user", "")
    ctx = Ctx(user=user, channel=channel)
    db = SessionLocal()
    try:
        room = room_for_channel(db, channel)
        if not room:
            return  # a memo outside a war room is just a memo
        msg = _fetch_message(channel, ts)
        if msg is None:
            ctx.reply("I could not read that message. Is it in a thread I was not added to?")
            return
        link = slack.try_call("chat.getPermalink", channel=channel, message_ts=ts)
        meta = {"channel": channel, "ts": ts, "permalink": (link or {}).get("permalink", "")}
        note = _message_note(db, msg)
    finally:
        db.close()
    _run_fn(ctx, "log", _log_entry, [room.case_number, note, meta])


def _mention(event: dict) -> None:
    if event.get("user") == slack.IDENTITY.get("bot_user_id") or event.get("bot_id"):
        return
    text = MENTION.sub("", event.get("text") or "").strip()
    ctx = Ctx(user=event.get("user", ""), channel=event.get("channel", ""),
              thread_ts=event.get("thread_ts") or event.get("ts", ""))
    parts = text.split()
    sub = parts[0].lower() if parts else "help"
    if sub in COMMANDS and sub != "ask":
        run(ctx, sub, parts[1:])
    else:
        run(ctx, "ask", parts)


def handle_event(body: dict) -> None:
    if not slack.allowed_team(body.get("team_id", "")):
        return
    event = body.get("event") or {}
    t = event.get("type")
    if t == "reaction_added":
        DEFER(lambda: _reaction(event))
    elif t == "app_mention":
        DEFER(lambda: _mention(event))


# ---------------------------------------------------------------- announcements (used by the feed)
def _seed_cases(db, exclude: str) -> None:
    """The first announcement ever (a declare before the feed has run) records the
    cases already active as history first, so they are not all announced at once."""
    if db.execute(select(Posted.id).where(Posted.kind == "case").limit(1)).first() is not None:
        return
    db.add(Posted(kind="case", ref="__seeded__", state="seed"))
    r = reach.get(IR, "/api/ir-cases", params={"status": "active"})
    for c in (r["data"] or []) if r["ok"] else []:
        if c["number"] != exclude:
            db.add(Posted(kind="case", ref=c["number"]))
    db.commit()


def _announce_case(db, case: dict, warroom: WarRoom | None, declared_by: Person | None = None) -> None:
    """Post a new case to the IR channel once."""
    _seed_cases(db, case["number"])
    if db.execute(select(Posted).where(Posted.kind == "case", Posted.ref == case["number"])).scalar_one_or_none():
        return
    row = Posted(kind="case", ref=case["number"], channel=settings.slack_ir_channel or "")
    db.add(row)
    db.commit()
    if not settings.slack_ir_channel:
        return
    head = (f":rotating_light: *New case* declared in Slack by {declared_by.name or declared_by.email}" if declared_by
            else f":rotating_light: *New case* ({blocks.esc(case.get('origin') or 'manual')}"
                 + (f" from {blocks.esc(case.get('source_module'))}" if case.get("source_module") else "") + ")")
    out = [blocks.md(head)] + blocks.case_card({**case, "link": ir_link(case)}, in_room=False,
                                               room=warroom.channel_name if warroom else "")
    res = slack.try_call("chat.postMessage", channel=settings.slack_ir_channel, text=f"New case {case['number']}", blocks=out)
    if res:
        row.ts = res.get("ts", "")
        db.commit()


_ = utcnow  # re-exported for the feed
