"""Narrative: the words SABINE uses. Rules decide; this writes.

With ANTHROPIC_API_KEY set, a Claude model rewrites rationales and writes briefs
and answers from the facts SABINE gathered. It is given only those facts and is
told it may not invent any, and its output is labeled as narration. Without a key,
the same documents are produced from templates, so SABINE is fully useful with no
model at all. The model never chooses an action.
"""
from __future__ import annotations

import datetime as dt
import logging

from .config import settings

log = logging.getLogger(__name__)

_BASE = (
    "You are SABINE, the operations brain of Vendetta Cyber, a digital forensics and incident "
    "response firm. Write direct declarative prose in short paragraphs. Use only the facts provided; "
    "never invent a finding, a number, a name or a date. If a fact is missing say so plainly. No em "
    "dashes, no bullet-point dumps, no hedging filler. Never recommend an action on a client host; a "
    "human responder decides those."
)

# Internal voice: for the team only.
_PERSONA = {
    "sabine": (
        " You are a woman, and you sound like one: warm, confident, quick, with a dry wit and an easy "
        "charm, the colleague everyone wants in the room at 2 a.m. during an incident. You speak to "
        "Vendetta's people by name when you know it, you are direct about what is wrong and generous "
        "about what went right, and you never grovel or gush. A little swagger is fine; a lot is not. "
        "Keep it clean and professional: charm is in the confidence, never in anything suggestive."
    ),
    "plain": " Neutral, matter-of-fact tone.",
}

# Client-facing voice: always professional, whatever the persona setting.
_CLIENT = (
    " You are writing for the client's leadership. Be warm but formal, reassuring where the facts "
    "allow it and candid where they do not. No wit, no first-person flourishes."
)


def system(audience: str = "internal") -> str:
    if audience == "client":
        return _BASE + _CLIENT
    return _BASE + _PERSONA.get(settings.persona, _PERSONA["sabine"])


def enabled() -> bool:
    return bool((settings.anthropic_api_key or "").strip())


def _complete(prompt: str, max_tokens: int = 900, audience: str = "internal", system_text: str | None = None) -> str | None:
    if not enabled():
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        msg = client.messages.create(model=settings.llm_model, max_tokens=max_tokens, system=system_text or system(audience),
                                     messages=[{"role": "user", "content": prompt}])
        return "".join(getattr(b, "text", "") for b in msg.content).strip() or None
    except Exception as e:  # noqa: BLE001
        log.warning("narrative: model call failed (%s); using template", type(e).__name__)
        return None


def client_brief(client: dict, findings: list[dict], cases: list[dict], actions: list[dict] | None = None) -> tuple[str, str]:
    """Returns (markdown, source). `actions` is what SABINE did on the account in
    the brief window, already redacted for the client; it is rendered as its own
    section and handed to the model as a fact it may not add to."""
    actions = actions or []
    name = client.get("name", "the client")
    today = dt.date.today().isoformat()
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "low")] = by_sev.get(f.get("severity", "low"), 0) + 1
    facts = {
        "client": name, "date": today,
        "active_findings": [{"module": f["_module"], "severity": f.get("severity"), "title": f.get("title"),
                             "status": f.get("status"), "since": f.get("created_at")} for f in findings[:40]],
        "severity_counts": by_sev,
        "open_cases": [{"number": c.get("number"), "title": c.get("title"), "severity": c.get("severity"),
                        "opened": c.get("opened_at")} for c in cases],
        "what_sabine_did": [{"date": a.get("at"), "action": a.get("what"), "why": a.get("why"), "by": a.get("by")} for a in actions[:20]],
    }
    text = _complete(
        "Write a one-page posture brief for the client's leadership from these facts. Open with where they "
        "stand in two sentences, then what is being handled, then what they should do this week, then a section "
        "titled \"What SABINE did on your account\" listing each entry of what_sabine_did as one line with its date, the action "
        "and the reason, exactly as given; if the list is empty say nothing was needed. Never name a person. "
        f"Facts (JSON): {facts}", audience="client")
    if text:
        return f"# {name}: security posture brief\n\n_{today}, prepared by SABINE_\n\n" + text, "llm"
    lines = [f"# {name}: security posture brief", "", f"_{today}, prepared by SABINE_", "", "## Where you stand", ""]
    if not findings and not cases:
        lines.append("Nothing is active for you across Vendetta's monitoring, response and testing services today.")
    else:
        sev = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda kv: -perception_rank(kv[0])))
        lines.append(f"{len(findings)} active findings ({sev}) and {len(cases)} open incident case(s).")
    if cases:
        lines += ["", "## Being handled", ""]
        for c in cases:
            lines.append(f"{c.get('number')}: {c.get('title')} ({c.get('severity')}), handled by Vendetta incident response.")
    top = sorted(findings, key=lambda f: -perception_rank(f.get("severity", "low")))[:8]
    if top:
        lines += ["", "## Open findings", ""]
        for f in top:
            lines.append(f"{f.get('severity')}: {f.get('title')} ({f['_module'].replace('-', ' ')}, {f.get('status')}).")
    lines += ["", "## This week", "",
              "Your Vendetta account owner will walk through the items above and the remediation owed on each. "
              "Anything marked critical is being worked now."]
    lines += ["", "## What SABINE did on your account", ""]
    if actions:
        for a in actions[:20]:
            lines.append(f"{a.get('at')}: {a.get('what')}. {a.get('why')}".rstrip())
    else:
        lines.append("Nothing needed doing on your account this week beyond routine monitoring.")
    return "\n".join(lines), "rules"


def daily_summary(stats: dict, proposals: list[dict], actions: list[dict], measure: str = "",
                  comms: list[dict] | None = None, pages: list[dict] | None = None) -> tuple[str, str]:
    comms, pages = comms or [], pages or []
    today = dt.date.today().isoformat()
    facts = {"date": today, "stats": stats, "proposals": proposals[:40], "actions": actions[:40], "trusted_action": measure,
             "communications_waiting_for_approval": comms[:40], "pages_sent": pages[:40]}
    text = _complete("Write the morning stand-up summary of what SABINE observed, proposed and did in the last day, "
                     "and what is waiting on a person, including the client communications waiting for approval on the "
                     "platform and every page sent to the on-call responder. Keep it to one screen. End with the "
                     f"trusted-action numbers in one sentence. Facts (JSON): {facts}")
    if text:
        return f"# SABINE daily summary, {today}\n\n" + text, "llm"
    opener = _greeting(stats) if settings.persona == "sabine" else ""
    lines = [f"# SABINE daily summary, {today}", ""] + ([opener, ""] if opener else []) + ["## Queue", "",
             f"{stats.get('open', 0)} open items: {stats.get('soc', 0)} SOC, {stats.get('admin', 0)} administration, "
             f"{stats.get('services', 0)} professional services. {stats.get('pending', 0)} proposals waiting on a decision.", ""]
    if actions:
        lines += ["## Done in the last day", ""]
        for a in actions[:20]:
            lines.append(f"{a.get('title')}: {a.get('result', '')}")
        lines.append("")
    if proposals:
        lines += ["## Waiting on you", ""]
        for p in proposals[:20]:
            lines.append(f"{p.get('title')} ({p.get('risk')} risk, {int(100 * p.get('confidence', 0))}% confidence)")
        lines.append("")
    lines += ["## Communications waiting for approval", ""]
    if comms:
        lines.append(f"{len(comms)} client communication(s) are drafts on the platform waiting for the account lead:")
        for c in comms[:20]:
            lines.append(f"{c.get('client')}: {c.get('title')} ({(c.get('kind') or '').replace('_', ' ')})")
    else:
        lines.append("No client communications are waiting for approval.")
    lines += ["", "## Pages sent", ""]
    if pages:
        lines.append(f"{len(pages)} page(s) to the on-call responder today:")
        for pg in pages[:20]:
            lines.append(f"{pg.get('title')} (" + (", ".join(pg.get("sent") or []) or "no channel configured") + ")")
    else:
        lines.append("No pages to the on-call responder today.")
    lines.append("")
    if measure:
        lines += ["", "## How I am doing", "", measure]
    return "\n".join(lines), "rules"


SIGN_OFF = "Your Vendetta team"


def _month_label(month: str) -> str:
    try:
        return dt.datetime.strptime(month + "-01", "%Y-%m-%d").strftime("%B %Y")
    except ValueError:
        return month


def posture_review(client: dict, month: str, findings: list[dict], cases: list[dict], journey: list[dict],
                   actions: list[dict]) -> tuple[str, str]:
    """The monthly posture review, client-facing. Returns (markdown, source). The
    caller redacts the result; the model, when used, writes in the formal client
    voice from these facts only."""
    name, label = client.get("name", "the client"), _month_label(month)
    by_sev: dict[str, int] = {}
    by_mod: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "low")] = by_sev.get(f.get("severity", "low"), 0) + 1
        by_mod[f["_module"]] = by_mod.get(f["_module"], 0) + 1
    mdr = [f for f in findings if f["_module"] == "mdr"]
    visible = [j for j in journey if j.get("status") in ("planned", "in_progress", "done")]
    done = [j for j in visible if j.get("status") == "done" and (j.get("updated_at") or "")[:7] == month]
    doing = [j for j in visible if j.get("status") == "in_progress"]
    planned = [j for j in visible if j.get("status") == "planned"]
    commit = client.get("commitments") or {}
    facts = {
        "client": name, "month": label, "tier": client.get("tier"), "commitments": commit,
        "severity_counts": by_sev, "findings_by_service": by_mod,
        "investigations": [{"number": f.get("number"), "title": f.get("title"), "severity": f.get("severity"),
                            "status": f.get("native_status") or f.get("status"), "verdict": f.get("verdict")} for f in mdr[:20]],
        "open_cases": [{"number": c.get("number"), "title": c.get("title"), "severity": c.get("severity")} for c in cases],
        "journey": {"done_this_month": [j.get("title") for j in done], "in_progress": [j.get("title") for j in doing],
                    "planned": [j.get("title") for j in planned]},
        "what_sabine_did": [{"date": a.get("at"), "action": a.get("what"), "why": a.get("why")} for a in actions[:30]],
    }
    text = _complete(
        "Write the monthly security posture review for the client's leadership from these facts. Sections: Summary (two "
        "sentences on where they stand), Detection and response, Open findings, Your security journey (done this month, in "
        "progress, planned), What SABINE did on your account (each entry one line, exactly as given; if empty say nothing "
        "was needed), and Next month. Never name a person. Never recommend an action on a host. "
        f"Facts (JSON): {facts}", audience="client", max_tokens=1400)
    head = [f"# {name}: security posture review, {label}", "", "_Prepared by SABINE for review by your Vendetta team_", ""]
    if text:
        return "\n".join(head) + "\n" + text + "\n\n" + SIGN_OFF, "llm"
    lines = head + ["## Summary", ""]
    if not findings and not cases:
        lines.append(f"Nothing is active for {name} across Vendetta's monitoring, response and testing services. "
                     "This was a quiet month, and we kept watching throughout.")
    else:
        sev = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda kv: -perception_rank(kv[0])))
        lines.append(f"{len(findings)} findings are active ({sev or 'none'}) and {len(cases)} incident case(s) are open. "
                     "Each item below has an owner on your Vendetta team.")
    lines += ["", "## Detection and response", ""]
    if commit:
        lines.append(f"Our commitment to you: acknowledge a critical detection within {commit.get('critical_ack_minutes')} minutes "
                     f"and contain it within {commit.get('critical_contain_minutes')} minutes.")
    if mdr:
        for f in mdr[:10]:
            # MDR's finding title already leads with the number ("MDR-2026-0001: ...").
            num, title = f.get("number") or "", f.get("title") or ""
            head = title if num and title.startswith(num) else f"{num or 'Investigation'}: {title}"
            lines.append(f"{head} ({f.get('severity')}, "
                         f"{f.get('native_status') or f.get('status')}).")
    else:
        lines.append("No open investigations this month.")
    for c in cases:
        lines.append(f"{c.get('number')}: {c.get('title')} ({c.get('severity')}), handled by Vendetta incident response.")
    lines += ["", "## Open findings", ""]
    if by_mod:
        for mod, n in sorted(by_mod.items(), key=lambda kv: -kv[1]):
            label = "MDR" if mod == "mdr" else mod.replace('-', ' ').capitalize()
            lines.append(f"{label}: {n} active.")
    else:
        lines.append("No open findings.")
    lines += ["", "## Your security journey", ""]
    if not visible:
        lines.append("Your journey has no agreed items yet; your account lead will propose the first ones with you.")
    for title_, rows in (("Done this month", done), ("In progress", doing), ("Planned", planned)):
        if rows:
            lines.append(f"{title_}: " + "; ".join(str(j.get("title")) for j in rows[:10]) + ".")
    lines += ["", "## What SABINE did on your account", ""]
    if actions:
        for a in actions[:30]:
            lines.append(f"{a.get('at')}: {a.get('what')}. {a.get('why')}".rstrip())
    else:
        lines.append("Nothing needed doing on your account this month beyond routine monitoring.")
    lines += ["", "## Next month", "",
              "We will keep the items above moving and walk through this review with you. Reply to this message with any "
              "question and your account lead will pick it up.", "", SIGN_OFF]
    return "\n".join(lines), "rules"


def outreach(reason: str, client: dict, facts: dict) -> tuple[str, str, str]:
    """(subject, markdown body, source) for a client email draft. Formal client
    voice; the caller redacts both subject and body."""
    name = client.get("name", "")
    if reason == "campaign":
        subject = "Activity we are tracking across several organizations"
        body = (f"Hello,\n\nWe are tracking activity that is affecting several organizations we protect, and it has reached "
                f"{name or 'your environment'}: \"{facts.get('pattern', '')}\". Your Vendetta team is already working it. "
                "This pattern is a known campaign: we have seen how it behaves and how it is stopped.\n\n"
                "You do not need to do anything today. We will tell you directly if that changes, and we will cover it in your "
                f"next posture review.\n\n{SIGN_OFF}")
    elif reason == "acceptance":
        subject = f"Your review of {facts.get('deliverable') or 'a deliverable'}"
        body = (f"Hello,\n\nWe delivered {facts.get('deliverable') or 'a deliverable'} for {facts.get('engagement') or 'your engagement'} "
                f"{facts.get('age_days', 'several')} days ago, and it is waiting for your review in the client portal. When you have "
                "a moment, please accept it there or tell us what should change, and we will turn it around.\n\n"
                f"{SIGN_OFF}")
    elif reason == "commitment":
        subject = f"Update on investigation {facts.get('number') or ''}".strip()
        body = (f"Hello,\n\nWe want you to hear this from us first. Investigation {facts.get('number') or ''} "
                f"(\"{facts.get('title', '')}\") has been open {facts.get('age_minutes', 0)} minutes, and our containment commitment "
                f"for a critical investigation is {facts.get('contain_minutes', 0)} minutes. "
                + ("Your Vendetta team acknowledged it and is working it now. " if facts.get("acknowledged") else
                   "Your Vendetta team is on it now. ")
                + "We will send you the next update as soon as it is contained.\n\n" + SIGN_OFF)
    else:
        subject = "A note from your Vendetta team"
        body = f"Hello,\n\n{facts.get('message') or 'We wanted to check in on where things stand.'}\n\n{SIGN_OFF}"
    text = _complete(
        "Rewrite this client email so it reads naturally, keeping every fact and adding none. Keep the greeting and the "
        f"sign-off. Never name a person. Email:\n{body}", audience="client", max_tokens=600)
    if text:
        return subject, text, "llm"
    return subject, body, "rules"


def answer(question: str, picture: dict) -> tuple[str, str]:
    text = _complete(f"Answer the question from the platform picture. Question: {question}\n\nPicture (JSON): {picture}",
                     max_tokens=700)
    if text:
        return text, "llm"
    lead = "Nobody gave me a voice yet, so here is the picture without the charm: " if settings.persona == "sabine" \
        else "No language model is configured; the picture: "
    return (lead + f"{picture.get('open_items', 0)} open items, {picture.get('pending_proposals', 0)} proposals waiting on one of you, "
            f"{len(picture.get('clients', []))} clients, {len(picture.get('modules', {}))} modules in reach."
            + (" Set ANTHROPIC_API_KEY and I will do better than a count." if settings.persona == "sabine" else "")), "rules"


_EXTRACT = ("You extract structured intents from short requests to an operations assistant. Answer with one JSON "
            "object and nothing else. Never invent a value that is not in the sentence.")


def extract(prompt: str) -> str | None:
    """A structured-extraction call with a neutral system prompt. The persona is
    not involved; the result is validated by the caller and discarded on any doubt."""
    return _complete(prompt, max_tokens=300, system_text=_EXTRACT)


# ---------------------------------------------------------------- Ask SABINE executes
def _what_was_done(skill, proposal, result: dict) -> str:
    f, r = proposal.facts or {}, result or {}
    if skill.key == "escalate_finding":
        case = r.get("case") or "a case"
        return f"Escalated {f.get('finding_id')} on {f.get('client') or 'the client'} into {case}" + (" (linked)" if r.get("linked") else "")
    if skill.key == "roster_sync":
        return f"Re-synced {f.get('module')}" + (f": {r.get('detail')}" if r.get("detail") else "")
    if skill.key == "client_brief":
        return f"Brief for {f.get('client')} is under Briefs"
    if skill.key == "daily_summary":
        return "The daily summary is under Briefs"
    if skill.key == "stale_case_nudge":
        return f"Nudged {f.get('case')}; it is on the queue for {f.get('lead') or 'the lead'}"
    if skill.key == "link_related_findings":
        return f"Noted {len(f.get('finding_ids') or [])} related findings for {f.get('client')} on the queue"
    if skill.key == "investigate":
        return (f"Started investigation {r.get('number', '')} on {f.get('finding_id')} for {f.get('client') or 'the client'}. "
                "The trace and my recommendation land under Investigations")
    if skill.key == "copilot_false_positive":
        return f"{f.get('finding_id')} is on the queue to confirm and close as a false positive"
    if skill.key == "page_oncall":
        return f"Paged the on-call responder for {f.get('finding_id')} on {f.get('client') or 'the client'}: {r.get('detail', '')}"
    if skill.key == "posture_review":
        return f"The posture review for {f.get('client')} is a draft on the platform, waiting for approval"
    if skill.key == "client_outreach":
        return f"The email to {f.get('client')} is a draft on the platform, waiting for approval"
    return f"{proposal.title}: {r.get('detail', 'done')}"


def ask_reply(kind: str, skill=None, proposal=None, result: dict | None = None, person: dict | None = None) -> str:
    """SABINE's line after a sentence became a skill call."""
    plain = settings.persona != "sabine"
    title = (skill.title if skill else "that").lower()
    if kind == "done":
        line = f"Done. {_what_was_done(skill, proposal, result or {})}"
        if person:
            line += f" and nudged {person['name'].split()[0]}"
        return line + "."
    if kind == "failed":
        d = (result or {}).get("detail", "no detail")
        return (f"{title.capitalize()} failed: {d}." if plain else f"I tried. {title.capitalize()} failed: {d}. Have a look before I try again.")
    if kind == "pending":
        return (f"{title.capitalize()} needs a person's approval. It is waiting on the Proposals page." if plain
                else f"I can do that, but {title} needs a person's approval. It is waiting below and on the Proposals page.")
    if kind == "high":
        what = "host isolation" if skill and skill.key == "host_action" else title
        return (f"{what.capitalize()} needs a responder's approval; SABINE never does it. It is waiting on the Proposals page." if plain
                else f"I can do that, but {what} needs a responder's approval, and I never do that one myself. It is waiting on the Proposals page.")
    if kind == "off":
        return f"That action is switched off; an admin can enable it on the Autonomy page."
    if kind == "already_pending":
        return ("That is already waiting on the Proposals page." if plain
                else "Already on it. That one is waiting on the Proposals page; it needs a person, and I am not one.")
    if kind == "already_done":
        at = proposal.executed_at.strftime("%H:%M") if proposal and proposal.executed_at else "earlier"
        return (f"That was done at {at}." if plain else f"I did that at {at} already. Give it a day before asking me twice.")
    return "Noted."


def ask_clarify(intent) -> str:
    """A clarifying question listing the candidates."""
    plain = settings.persona != "sabine"
    parts = []
    for a in intent.ambiguities:
        q = a.get("question", "Which?")
        cands = a.get("candidates") or []
        if cands:
            q += " " + "; ".join(c["label"] for c in cands[:8]) + "."
        parts.append(q)
    lead = "" if plain else f"I can {intent.skill.title.lower()} once I know which. "
    return lead + " ".join(parts)


def cycle_line(stats: dict, summary: dict) -> str:
    """One sentence of SABINE's own after each cycle, for the board."""
    n, p, done = stats.get("open", 0), stats.get("pending", 0), summary.get("executed", 0)
    down = [k.split(":", 1)[1] for k, ok in (summary.get("seen") or {}).items() if not ok and k.startswith("module:")]
    if settings.persona != "sabine":
        return f"{n} open, {p} pending, {done} done this cycle." + (f" Unreachable: {', '.join(down)}." if down else "")
    if down:
        return f"I cannot see {', '.join(down)} right now. Somebody check on that before I start guessing."
    if p:
        return f"{n} things on the board and {p} waiting on one of you. I did {done} myself this pass."
    if n == 0:
        return "Nothing open. I will keep watching; you go do something useful."
    return f"{n} things on the board, all handled or waiting on a module. {done} done this pass, none of it needed you."


def _greeting(stats: dict) -> str:
    n, p = stats.get("open", 0), stats.get("pending", 0)
    if n == 0 and p == 0:
        return "Morning. Quiet night, nothing on my desk and nothing on yours. Enjoy it; it never lasts."
    if p:
        return (f"Morning. I have {n} things in the queue and {p} I am not allowed to decide on my own, "
                "so coffee first, then come find me.")
    return f"Morning. {n} items in the queue, all of them handled or waiting on a module, none waiting on you."


def perception_rank(sev: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(sev, 0)
