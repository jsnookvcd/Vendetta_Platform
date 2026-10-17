"""The external-tool commands: what a responder can pull or do in the outside
systems from Slack, always through the module that owns that system.

- /ir darkweb [client] [days]     dark web monitoring: the exposure report, summary plus PDF
- /ir shodan [client] [targets]   vulnerability management: Shodan exposure check, recorded as findings
- /ir host <name> [client]        managed services: the EDR record (CrowdStrike, SentinelOne, Huntress)
- /ir contain <host> [reason]     managed services: request network containment; a second person approves
- /ir release <host> [reason]     managed services: lift containment (runs at once)

In a war room the client comes from the case and every result is noted on the
case timeline. Outside one, name the client. The owning module enforces its own
rules (grants, ACTIONS_READONLY, the two-person rule); Slack never talks to a
vendor directly and never holds a vendor credential.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re

from sqlalchemy import select

from . import blocks, identity, reach, responder, slack
from .db import Posted, SessionLocal, audit
from .identity import Person, Refused
from .responder import DW, IR, MS, VM, Ctx

DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
CONTAIN = {"crowdstrike": "cs_contain", "sentinelone": "s1_disconnect", "huntress": "h_isolate"}
RELEASE = {"crowdstrike": "cs_lift", "sentinelone": "s1_reconnect", "huntress": "h_release"}
TOOL_NAME = {"crowdstrike": "CrowdStrike Falcon", "sentinelone": "SentinelOne", "huntress": "Huntress",
             "acronis": "Acronis", "superops": "SuperOps"}
STATUS_ICON = {"pending": ":hourglass_flowing_sand:", "done": ":white_check_mark:", "failed": ":warning:",
               "blocked": ":no_entry:", "rejected": ":x:", "expired": ":clock3:"}


# ---------------------------------------------------------------- who the command is about
def _clients(module: str) -> list[dict]:
    r = reach.get("platform", "/api/platform/clients", params={"module": module})
    return [{"id": c["id"], "name": c["name"]} for c in ((r["data"] or {}).get("clients") or [])] if r["ok"] else []


def resolve_client(db, ctx: Ctx, person: Person, module: str, words: list[str]) -> tuple[dict, str]:
    """(client, case_number). A war room supplies its case's client; otherwise the
    words name the client among those that have this module turned on."""
    room = responder.room_for_channel(db, ctx.channel)
    if room and not words:
        case = responder.fetch_case(room.case_number, person.email)
        pid = case["client"].get("platform_client_id") or ""
        if not pid:
            raise Refused("This case's client is not linked to the platform roster, so I cannot find it in other modules.")
        return {"id": pid, "name": case["client"]["name"]}, room.case_number
    name = " ".join(words).strip()
    if not name:
        raise Refused("Which client? Run this in a war room, or name the client after the command.")
    clients = _clients(module)
    match, hits = responder._match_client(clients, name)
    if match is None:
        if hits:
            raise Refused("More than one client matches: " + ", ".join(c["name"] for c in hits[:8]) + ".")
        raise Refused(f"No client with {responder.MODULE_NAMES[module]} turned on matches '{name}'.")
    return match, (room.case_number if room else "")


def _note(case_number: str, person: Person, text: str) -> None:
    if case_number:
        reach.post(IR, f"/api/ir-cases/{case_number}/updates", person=person.email,
                   json_body={"note": text, "internal_only": True})


def _in_room(db, ctx: Ctx) -> bool:
    return responder.room_for_channel(db, ctx.channel) is not None


# ---------------------------------------------------------------- dark web
def cmd_darkweb(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    days = 30
    if args and args[-1].isdigit():
        days, args = max(1, min(int(args[-1]), 365)), args[:-1]
    client, case = resolve_client(db, ctx, person, DW, args)
    r = reach.get(DW, f"/api/clients/platform/{client['id']}/report", person=person.email, params={"days": days}, timeout=60.0)
    if not r["ok"]:
        raise Refused(f"Dark web monitoring did not answer: {r['detail']}")
    d = r["data"] or {}
    sev = d.get("by_severity") or {}
    lines = [f"*Dark web exposure: {blocks.esc(d.get('client', client['name']))}*, last {days} days",
             f"{d.get('total', 0)} hits  ({sev.get('critical', 0)} critical, {sev.get('high', 0)} high, "
             f"{sev.get('medium', 0)} medium, {sev.get('low', 0)} low)"]
    out = [blocks.md("\n".join(lines))]
    if d.get("credential_count"):
        creds = "\n".join(f"{blocks.SEV_ICON.get(c['severity'], '')} `{blocks.esc(c['matched'])}`" for c in d.get("credentials", [])[:8])
        out.append(blocks.md(f"*Exposed credentials ({d['credential_count']})*\n{creds}"))
    if d.get("leak_posts"):
        leaks = "\n".join(f"{blocks.SEV_ICON.get(h['severity'], '')} {blocks.esc(h['group'] or h['kind'])}: {blocks.esc(h['title'])}"
                          for h in d["leak_posts"][:5])
        out.append(blocks.md(f"*Leak site and forum posts*\n{leaks}"))
    if d.get("access_broker"):
        out.append(blocks.md(f"*Access-broker listings matching the profile:* {len(d['access_broker'])}"))
    acts = "\n".join(f"{i}. {blocks.esc(a['title'])}" for i, a in enumerate(d.get("actions") or [], 1))
    if acts:
        out.append(blocks.md(f"*Recommended*\n{acts}"))
    out.append(blocks.ctx(f"Pulled by {blocks.esc(person.name or person.email)}. "
                          f"{d.get('evidence_captured', 0)} evidence captures on file."))
    in_room = _in_room(db, ctx)
    ctx.reply(f"Dark web exposure for {d.get('client', client['name'])}", out, public=in_room)
    pdf, err = reach.get_bytes(DW, f"/api/clients/platform/{client['id']}/report.pdf", person=person.email,
                               params={"days": days})
    if pdf:
        target = ctx.channel if in_room else slack.dm_channel(person.slack_id)
        safe = re.sub(r"[^A-Za-z0-9]+", "_", client["name"]).strip("_")
        slack.upload(target, f"Vendetta_Dark_Web_Exposure_{safe}_{dt.date.today():%Y%m%d}.pdf", pdf,
                     title=f"Dark web exposure, {client['name']}, {days} days",
                     comment="" if in_room else "The full report, as asked.")
    elif err:
        ctx.reply(f"The summary is above; the PDF did not come through ({err}).")
    audit(db, "tool.darkweb", f"{client['name']} {days}d total={d.get('total', 0)}", slack_user=person.slack_id, actor=person.email)
    _note(case, person, f"Dark web report pulled from Slack ({days} days): {d.get('total', 0)} hits, "
                        f"{sev.get('critical', 0)} critical, {d.get('credential_count', 0)} exposed credentials.")


# ---------------------------------------------------------------- Shodan
def _is_target(word: str) -> bool:
    w = word.strip().lower().rstrip(".,")
    try:
        ipaddress.ip_network(w, strict=False) if "/" in w else ipaddress.ip_address(w)
        return True
    except ValueError:
        return bool(DOMAIN.match(w))


def cmd_shodan(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    responder._need(person, VM)
    words = [a for a in args if not _is_target(a)]
    targets = [a.strip().lower().rstrip(".,") for a in args if _is_target(a)]
    client, case = resolve_client(db, ctx, person, VM, words)
    body = {"targets": " ".join(targets)} if targets else {}
    r = reach.post(VM, f"/api/clients/platform/{client['id']}/shodan", person=person.email, json_body=body, timeout=180.0)
    if not r["ok"]:
        raise Refused(f"The Shodan check did not run: {r['detail']}")
    d = r["data"] or {}
    counts = d.get("counts") or {}
    hosts = d.get("hosts") or []
    head = (f"*Shodan exposure: {blocks.esc(d.get('client', client['name']))}*  "
            f"{len(hosts)} host{'s' if len(hosts) != 1 else ''} checked"
            + (f", {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {counts.get('medium', 0)} medium"
               if counts else ""))
    out = [blocks.md(head)]
    rows = []
    for h in hosts[:15]:
        label = f" ({blocks.esc(h['label'])})" if h.get("label") else ""
        if not h.get("known"):
            rows.append(f"`{h['ip']}`{label}  nothing indexed")
            continue
        risky = f"  :rotating_light: {blocks.esc(', '.join(h['risky']))}" if h.get("risky") else ""
        cves = f"  {len(h['cves'])} CVE{'s' if len(h['cves']) != 1 else ''}" if h.get("cves") else ""
        ports = ", ".join(str(p) for p in (h.get("ports") or [])[:12])
        rows.append(f"`{h['ip']}`{label}  ports {ports or 'none'}{risky}{cves}")
    if rows:
        out.append(blocks.md("\n".join(rows)))
    top = d.get("top") or []
    if top:
        out.append(blocks.md("*Worst first*\n" + "\n".join(
            f"{blocks.SEV_ICON.get(t['severity'], '')} {blocks.esc(t['title'])}  _{blocks.esc(t['asset'])}_" for t in top[:8])))
    notes = (d.get("errors") or []) + [f"ignored {x}" for x in (d.get("rejected") or [])]
    if notes:
        out.append(blocks.ctx(blocks.esc("; ".join(notes[:6]))))
    base = reach.public_url(VM)
    out.append(blocks.ctx("Findings are recorded in vulnerability management" + (f": {base}" if base else ".")))
    ctx.reply(f"Shodan exposure for {d.get('client', client['name'])}", out, public=_in_room(db, ctx))
    audit(db, "tool.shodan", f"{client['name']} hosts={len(hosts)} {counts}", slack_user=person.slack_id, actor=person.email)
    _note(case, person, f"Shodan exposure check from Slack: {len(hosts)} hosts, "
                        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high findings recorded in vulnerability management.")


# ---------------------------------------------------------------- hosts and containment
def _find_devices(db, ctx: Ctx, person: Person, args: list[str]) -> tuple[list[dict], dict, str, bool]:
    if not args:
        raise Refused("Which host? `/ir host WS01`, or outside a war room `/ir host WS01 Riverbend`.")
    host, rest = args[0], args[1:]
    client, case = resolve_client(db, ctx, person, MS, rest)
    r = reach.get(MS, "/api/devices", person=person.email, params={"platform_client_id": client["id"], "q": host})
    if not r["ok"]:
        raise Refused(f"Managed services did not answer: {r['detail']}")
    devs = (r["data"] or {}).get("devices") or []
    exact = [d for d in devs if d["hostname"].lower() == host.lower()]
    return (exact or devs), client, case, bool((r["data"] or {}).get("actions_readonly"))


def _device_blocks(d: dict, readonly: bool) -> list[dict]:
    last = blocks._ago(d.get("last_seen")) or "never"
    head = (f"*{blocks.esc(d['hostname'])}*  {TOOL_NAME.get(d['tool'], d['tool'])}  status *{blocks.esc(d.get('status') or 'unknown')}*"
            f"  last seen {last}\n{blocks.esc(d.get('platform') or '')} {blocks.esc(d.get('agent_version') or '')}".strip())
    out = [blocks.md(head)]
    if d.get("open_alerts"):
        out.append(blocks.md("\n".join(f"{blocks.SEV_ICON.get(a['severity'], '')} {blocks.esc(a['title'])}"
                                       for a in d["open_alerts"][:6])))
    acts = []
    for a in d.get("actions") or []:
        value = f"{d['platform_client_id']}|{d['id']}|{a['id']}"
        if a["id"] in CONTAIN.values():
            acts.append(blocks.button("Request containment", "host_request", value, style="danger"))
        elif a["id"] in RELEASE.values():
            acts.append(blocks.button(a["label"], "host_request", value))
    if d.get("link"):
        acts.append(blocks.button(f"Open in {TOOL_NAME.get(d['tool'], d['tool'])}", "open_tool", url=d["link"]))
    if acts and not readonly:
        out.append({"type": "actions", "elements": acts[:5]})
    elif readonly:
        out.append(blocks.ctx("Managed services is read-only: no tool action can run until an operator turns actions on."))
    return out


def cmd_host(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    devs, client, _, readonly = _find_devices(db, ctx, person, args)
    if not devs:
        raise Refused(f"No host matching '{args[0]}' for {client['name']} in managed services.")
    out = []
    for d in devs[:5]:
        out += _device_blocks(d, readonly) + [{"type": "divider"}]
    if len(devs) > 5:
        out.append(blocks.ctx(f"and {len(devs) - 5} more matches; be more specific"))
    audit(db, "tool.host", f"{client['name']} {args[0]} matches={len(devs)}", slack_user=person.slack_id, actor=person.email)
    ctx.reply(f"{len(devs)} host(s) matching {args[0]}", out[:49], public=_in_room(db, ctx))


def request_card(req: dict, *, decided: str = "") -> list[dict]:
    icon = STATUS_ICON.get(req["status"], "")
    head = (f"{icon} *{blocks.esc(req['action'])}* on *{blocks.esc(req['hostname'])}*  "
            f"({TOOL_NAME.get(req['tool'], req['tool'])}, {blocks.esc(req['client'])})")
    out = [blocks.md(head)]
    who = f"Requested by {blocks.esc(req['requested_by'])}"
    if req.get("reason"):
        who += f": {blocks.esc(req['reason'][:300])}"
    out.append(blocks.ctx(who))
    if req["status"] == "pending":
        out.append(blocks.ctx("Needs a second person with approval rights in managed services. "
                              "The requester cannot approve their own. Expires in 30 minutes."))
        out.append({"type": "actions", "elements": [
            blocks.button("Approve and run", "host_approve", req["id"], style="danger"),
            blocks.button("Reject", "host_reject", req["id"])]})
    else:
        line = decided or f"{req['status'].capitalize()}" + (f" by {req['decided_by']}" if req.get("decided_by") else "")
        if req.get("detail") and req["status"] != "done":
            line += f": {req['detail'][:300]}"
        out.append(blocks.ctx(blocks.esc(line)))
    return out


def _file_request(db, ctx: Ctx, person: Person, device: dict, action_id: str, reason: str, case: str) -> None:
    responder._need(person, MS)
    r = reach.post(MS, "/api/action-requests", person=person.email, json_body={
        "platform_client_id": device["platform_client_id"], "device_id": device["id"], "action_id": action_id,
        "reason": reason or "Requested from Slack", "source_ref": case})
    if not r["ok"]:
        raise Refused(f"Managed services refused: {r['detail']}")
    req = r["data"]
    in_room = _in_room(db, ctx)
    channel = ctx.channel if in_room else ""
    posted = None
    if channel:
        posted = slack.try_call("chat.postMessage", channel=channel, text=f"{req['action']} on {req['hostname']}: {req['status']}",
                                blocks=request_card(req))
    else:
        ctx.reply(f"{req['action']} on {req['hostname']}: {req['status']}", request_card(req))
    db.add(Posted(kind="action", ref=req["id"], channel=channel, ts=(posted or {}).get("ts", ""), state=req["status"]))
    db.commit()
    audit(db, f"tool.request.{req['status']}", f"{req['id']} {action_id} {req['hostname']} {req['client']}",
          slack_user=person.slack_id, actor=person.email)
    verb = "requested" if req["status"] == "pending" else req["status"]
    _note(case, person, f"{req['action']} on {req['hostname']} ({TOOL_NAME.get(req['tool'], req['tool'])}) {verb} from Slack"
                        + (f": {reason}" if reason else "") + ".")


def _contain_or_release(db, ctx: Ctx, person: Person, args: list[str], table: dict) -> None:
    responder._need(person, MS)
    if not args:
        raise Refused("Which host? `/ir contain WS01 <reason>`")
    room = responder.room_for_channel(db, ctx.channel)
    # In a war room everything after the host is the reason. Outside one the client
    # comes next and the reason after a colon: /ir contain WS01 Riverbend: beaconing
    rest = " ".join(args[1:])
    if room:
        host_args, reason = args[:1], rest
    else:
        client_part, _, reason = rest.partition(":")
        host_args = [args[0]] + client_part.split()
    devs, client, case, readonly = _find_devices(db, ctx, person, host_args)
    if readonly:
        raise Refused("Managed services is read-only: no tool action can run until an operator sets ACTIONS_READONLY=false.")
    devs = [d for d in devs if d["tool"] in table]
    if not devs:
        raise Refused(f"No EDR-managed host matching '{args[0]}' for {client['name']}.")
    if len(devs) > 1:
        out = [blocks.md(f"More than one host matches '{blocks.esc(args[0])}'. Pick one:")]
        for d in devs[:8]:
            out += _device_blocks(d, readonly)
        ctx.reply("Pick a host", out[:49])
        return
    _file_request(db, ctx, person, devs[0], table[devs[0]["tool"]], reason.strip(), case)


def cmd_contain(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _contain_or_release(db, ctx, person, args, CONTAIN)


def cmd_release(db, ctx: Ctx, person: Person, args: list[str]) -> None:
    _contain_or_release(db, ctx, person, args, RELEASE)


# ---------------------------------------------------------------- buttons
def _button_request(db, ctx: Ctx, person: Person, args: list) -> None:
    pid, device_id, action_id = args
    r = reach.get(MS, "/api/devices", person=person.email, params={"platform_client_id": pid})
    devs = ((r["data"] or {}).get("devices") or []) if r["ok"] else []
    d = next((x for x in devs if x["id"] == device_id), None)
    if d is None:
        raise Refused("That host is no longer listed in managed services.")
    room = responder.room_for_channel(db, ctx.channel)
    _file_request(db, ctx, person, d, action_id, "Requested from Slack", room.case_number if room else "")


def _button_decide(db, ctx: Ctx, person: Person, args: list) -> None:
    rid, approve, msg_ts = args
    responder._need(person, MS)
    r = reach.post(MS, f"/api/action-requests/{rid}/decide", person=person.email,
                   json_body={"approve": approve, "note": "Decided in Slack"}, timeout=60.0)
    req = r["data"] if isinstance(r["data"], dict) and r["data"].get("id") else None
    if not r["ok"] and r["status"] != 409:
        raise Refused(f"Managed services refused: {r['detail']}")
    if req is None:
        g = reach.get(MS, f"/api/action-requests/{rid}", person=person.email)
        req = g["data"] if g["ok"] else None
    if req is None:
        raise Refused("I could not read that request back from managed services.")
    row = db.execute(select(Posted).where(Posted.kind == "action", Posted.ref == rid)).scalar_one_or_none()
    if r["status"] == 409:
        decided = (r["data"] or {}).get("refused") or f"Already {req['status']}"
    elif req["status"] == "done":
        decided = f"Approved by {person.name or person.email} and carried out."
    elif req["status"] == "rejected":
        decided = f"Rejected by {person.name or person.email}."
    else:
        decided = f"Approved by {person.name or person.email}, but it did not go through: {req.get('detail') or req['status']}"
    channel, ts = (row.channel, row.ts) if row and row.ts else (ctx.channel, msg_ts)
    if row:
        row.state = req["status"]
        db.commit()
    if channel and ts:
        slack.try_call("chat.update", channel=channel, ts=ts, text=decided, blocks=request_card(req, decided=decided))
    if channel:
        slack.try_call("chat.postMessage", channel=channel, text=blocks.esc(f"{STATUS_ICON.get(req['status'], '')} "
                       f"{req['action']} on {req['hostname']}: {decided}"))
    else:
        ctx.reply(decided)
    audit(db, f"tool.decide.{req['status']}", f"{rid} {decided}", slack_user=person.slack_id, actor=person.email,
          ok=r["ok"])
    if r["ok"] and req.get("source_ref"):
        _note(req["source_ref"], person, f"{req['action']} on {req['hostname']}: {decided}")


ACTIONS = {"host_request", "host_approve", "host_reject", "open_tool"}


def on_action(payload: dict, ctx: Ctx, aid: str, value: str) -> None:
    if aid == "open_tool":
        return
    if aid == "host_request":
        try:
            pid, did, action_id = value.split("|")
        except ValueError:
            return
        responder.DEFER(lambda: responder._run_fn(ctx, "host_request", _button_request, [pid, did, action_id], modules=(MS,)))
    else:
        msg_ts = (payload.get("container") or {}).get("message_ts", "") or (payload.get("message") or {}).get("ts", "")
        responder.DEFER(lambda: responder._run_fn(ctx, "host_decide", _button_decide,
                                                  [value, aid == "host_approve", msg_ts], modules=(MS,)))


responder.COMMANDS.update({
    "darkweb": (cmd_darkweb, (DW,)),
    "dw": (cmd_darkweb, (DW,)),
    "shodan": (cmd_shodan, (VM,)),
    "exposure": (cmd_shodan, (VM,)),
    "host": (cmd_host, (MS,)),
    "contain": (cmd_contain, (MS,)),
    "isolate": (cmd_contain, (MS,)),
    "release": (cmd_release, (MS,)),
    "uncontain": (cmd_release, (MS,)),
})
responder.MENTION_READS.update({"host", "darkweb", "dw"})
_ = (SessionLocal, identity)
