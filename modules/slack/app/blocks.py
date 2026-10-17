"""Block Kit builders. Everything a responder sees in Slack is assembled here so
the wording and layout stay in one place."""
from __future__ import annotations

import datetime as dt

from .config import settings

SEV_ICON = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:",
            "low": ":white_circle:"}
STATUS_ICON = {"open": ":rotating_light:", "contained": ":shield:", "eradicated": ":broom:",
               "recovered": ":white_check_mark:", "closed": ":lock:"}
TASK_ICON = {"todo": ":white_square:", "in_progress": ":arrow_forward:", "blocked": ":no_entry:", "done": ":ballot_box_with_check:"}
WS_SHORT = {
    "Scoping and Containment": "Containment",
    "Forensics and Analysis": "Forensics",
    "Recovery and Restoration": "Recovery",
    "Notification and Legal": "Legal",
    "Resilience and Hardening": "Hardening",
}


def _t(text: str, limit: int = 2900) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def esc(text: str) -> str:
    """Slack mrkdwn escaping for text that came from someone else."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def md(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": _t(text)}}


def ctx(text: str) -> dict:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": _t(text, 2000)}]}


def _ago(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        t = dt.datetime.fromisoformat(iso)
    except ValueError:
        return ""
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    mins = int((dt.datetime.now(dt.timezone.utc) - t).total_seconds() // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins}m ago"
    if mins < 60 * 48:
        return f"{mins // 60}h {mins % 60}m ago"
    return f"{mins // 1440}d ago"


def button(text: str, action_id: str, value: str = "", style: str = "", url: str = "") -> dict:
    b = {"type": "button", "text": {"type": "plain_text", "text": text[:75]}, "action_id": action_id}
    if value:
        b["value"] = value[:2000]
    if style:
        b["style"] = style
    if url:
        b["url"] = url
    return b


def case_line(c: dict) -> str:
    return (f"{SEV_ICON.get(c.get('severity'), '')} *{c['number']}*  {esc(c['client']['name'])}  "
            f"{STATUS_ICON.get(c.get('status'), '')} {c.get('status', '')}  lead: {esc(c.get('lead') or 'unassigned')}")


PRIVILEGED_TITLE = "Privileged and confidential: details in the IR hub"


def title_of(c: dict) -> str:
    """A counsel-directed case never puts its title into Slack."""
    return PRIVILEGED_TITLE if c.get("privileged") else (c.get("title") or "")


def case_card(c: dict, *, in_room: bool = False, room: str = "") -> list[dict]:
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{SEV_ICON.get(c.get('severity'), '')} {c.get('severity')}"},
        {"type": "mrkdwn", "text": f"*Status*\n{STATUS_ICON.get(c.get('status'), '')} {c.get('status')}"},
        {"type": "mrkdwn", "text": f"*Lead*\n{esc(c.get('lead') or 'unassigned')}"},
        {"type": "mrkdwn", "text": f"*Opened*\n{_ago(c.get('opened_at'))} ({esc(c.get('origin') or 'manual')})"},
    ]
    progress = []
    for w in c.get("workstreams") or []:
        cards = w.get("cards") or {}
        total = sum(cards.values())
        if total:
            progress.append(f"{WS_SHORT.get(w['name'], w['name'])} {cards.get('done', 0)}/{total}")
    out = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{c['number']}  {c['client']['name']}"[:150]}},
        md(f"*{esc(title_of(c))}*"),
        {"type": "section", "fields": fields},
    ]
    if progress:
        out.append(ctx("Cards done: " + "   ".join(progress)))
    acts = [button("Sitrep", "sitrep", c["number"]), button("Tasks", "tasks", c["number"])]
    if not in_room:
        acts.append(button(f"Join #{room}" if room else "Open war room", "warroom", c["number"]))
    if c.get("link"):
        acts.append(button("Open in IR hub", "open_ir", url=c["link"]))
    out.append({"type": "actions", "elements": acts})
    if c.get("privileged"):
        out.append(ctx(":lock: Counsel-directed. Keep analysis out of Slack; record it in the IR hub."))
    return out


def sitrep(c: dict, *, in_room: bool = False, room: str = "") -> list[dict]:
    out = case_card(c, in_room=in_room, room=room)
    open_tasks = [t for t in c.get("tasks") or [] if t["status"] != "done"]
    if open_tasks:
        lines = [f"{TASK_ICON.get(t['status'], '')} {WS_SHORT.get(t['workstream'], t['workstream'])}: "
                 f"{esc(t['title'])}" + (f"  ({esc(t['owner'])})" if t.get("owner") else "")
                 for t in open_tasks[:15]]
        more = f"\n_and {len(open_tasks) - 15} more_" if len(open_tasks) > 15 else ""
        out.append(md("*Open cards*\n" + "\n".join(lines) + more))
    ups = [] if c.get("privileged") else [u for u in c.get("updates") or [] if u.get("kind") in ("note", "status", "system", "finding")][:6]
    if ups:
        lines = [f"`{_ago(u['at'])}` {esc(u['actor'])}: {esc(u['note'][:240])}" for u in ups]
        out.append(md("*Latest on the timeline*\n" + "\n".join(lines)))
    return out


def task_list(c: dict) -> list[dict]:
    open_tasks = [t for t in c.get("tasks") or [] if t["status"] != "done"]
    out = [md(f"*{c['number']}* open cards ({len(open_tasks)})")]
    if not open_tasks:
        out.append(ctx("Nothing open. Add one with `" + settings.slack_command + " task <title>`."))
        return out
    for t in open_tasks[:40]:
        opts = [{"text": {"type": "plain_text", "text": label}, "value": f"{c['number']}|{t['id']}|{st}"}
                for st, label in (("in_progress", "Start"), ("blocked", "Blocked"), ("done", "Done"))
                if st != t["status"]]
        out.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _t(f"{TASK_ICON.get(t['status'], '')} *{WS_SHORT.get(t['workstream'], t['workstream'])}*  "
                                                  f"{esc(t['title'])}" + (f"\n_{esc(t['owner'])}_" if t.get("owner") else ""))},
            "accessory": {"type": "overflow", "action_id": "task_move", "options": opts},
        })
    return out


def proposal_card(p: dict, *, console_url: str = "", decided: str = "") -> list[dict]:
    facts = p.get("facts") or {}
    client = facts.get("client") or ""
    head = f":brain: *SABINE proposes:* {esc(p.get('title') or p.get('action'))}"
    out = [md(head), md(esc((p.get("rationale") or "")[:900]))]
    out.append(ctx(f"{p.get('action')}  risk {p.get('risk')}  confidence {round(float(p.get('confidence') or 0) * 100)}%"
                   + (f"  client {esc(client)}" if client else "")))
    if decided:
        out.append(ctx(decided))
        return out
    if p.get("risk") == "high":
        out.append(ctx("High risk. A person with the grant decides this in the SABINE console."))
        if console_url:
            out.append({"type": "actions", "elements": [button("Decide in SABINE", "open_sabine", url=console_url)]})
        return out
    acts = [button("Approve", "proposal_approve", p["id"], style="primary"),
            button("Reject", "proposal_reject", p["id"], style="danger")]
    if console_url:
        acts.append(button("Open in SABINE", "open_sabine", url=console_url))
    out.append({"type": "actions", "elements": acts})
    return out


def declare_modal(clients: list[dict], channel: str, preset_desc: str = "") -> dict:
    opts = [{"text": {"type": "plain_text", "text": c["name"][:75]}, "value": c["id"][:150]} for c in clients[:100]]
    client_block = {
        "type": "input", "block_id": "client", "label": {"type": "plain_text", "text": "Client"},
        "element": {"type": "static_select", "action_id": "v", "options": opts,
                    "placeholder": {"type": "plain_text", "text": "Choose the client"}},
    } if opts else {
        "type": "input", "block_id": "client_name", "label": {"type": "plain_text", "text": "Client name"},
        "element": {"type": "plain_text_input", "action_id": "v"},
    }
    sev_opts = [{"text": {"type": "plain_text", "text": s.capitalize()}, "value": s} for s in ("critical", "high", "medium", "low")]
    return {
        "type": "modal", "callback_id": "declare", "private_metadata": channel,
        "title": {"type": "plain_text", "text": "Declare an incident"},
        "submit": {"type": "plain_text", "text": "Declare"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            client_block,
            {"type": "input", "block_id": "severity", "label": {"type": "plain_text", "text": "Severity"},
             "element": {"type": "static_select", "action_id": "v", "options": sev_opts, "initial_option": sev_opts[1]}},
            {"type": "input", "block_id": "desc", "label": {"type": "plain_text", "text": "What is happening"},
             "element": {"type": "plain_text_input", "action_id": "v", "multiline": True, "max_length": 2000,
                         **({"initial_value": preset_desc[:2000]} if preset_desc else {})}},
            {"type": "input", "block_id": "room", "optional": True, "label": {"type": "plain_text", "text": "War room"},
             "element": {"type": "checkboxes", "action_id": "v",
                         "options": [{"text": {"type": "plain_text", "text": "Open a war room channel and invite me"}, "value": "yes"}],
                         "initial_options": [{"text": {"type": "plain_text", "text": "Open a war room channel and invite me"}, "value": "yes"}]}},
        ],
    }


def log_modal(cases: list[dict], meta: str, note: str) -> dict:
    opts = [{"text": {"type": "plain_text", "text": f"{c['number']} {c['client']['name']}"[:75]}, "value": c["number"]}
            for c in cases[:100]]
    return {
        "type": "modal", "callback_id": "log_to_case", "private_metadata": meta[:3000],
        "title": {"type": "plain_text", "text": "Log to case timeline"},
        "submit": {"type": "plain_text", "text": "Log it"},
        "blocks": [
            {"type": "input", "block_id": "case", "label": {"type": "plain_text", "text": "Case"},
             "element": {"type": "static_select", "action_id": "v", "options": opts}},
            {"type": "input", "block_id": "note", "label": {"type": "plain_text", "text": "Entry"},
             "element": {"type": "plain_text_input", "action_id": "v", "multiline": True, "max_length": 3000,
                         "initial_value": note[:3000]}},
        ],
    }


def help_text() -> str:
    c = settings.slack_command
    r = f":{settings.memo_reaction}:"
    return "\n".join([
        "*Slack responder*  every entry lands on the IR hub's signed case timeline under your name.",
        "",
        "*Anywhere*",
        f"`{c} declare` open an incident (or `{c} declare critical Riverbend: ransom note on FS01`)",
        f"`{c} cases` active cases    `{c} sitrep VCD-IR-2026-781`    `{c} room VCD-IR-2026-781` open its war room",
        f"`{c} ask <question>` ask SABINE (or mention her)",
        "",
        "*In a war room* (the case comes from the channel)",
        f"`{c} sitrep`  `{c} note <text>`  `{c} status contained`  `{c} sev critical`  `{c} lead @dan`",
        f"`{c} task forensics: image FS01 @dan`  `{c} tasks`  `{c} page <message>`",
        f"React {r} on any message to log it to the timeline, or use the message shortcut *Log to IR case*.",
        f"`{c} link VCD-IR-2026-781` binds an existing channel to a case.",
        "",
        "_Host actions stay in managed services under the two-person rule. High-risk SABINE proposals are decided in her console._",
    ])
