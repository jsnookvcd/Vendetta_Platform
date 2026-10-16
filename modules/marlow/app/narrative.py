"""Narrative: the words MARLOW uses. Rules decide; this writes.

With ANTHROPIC_API_KEY set, a Claude model rewrites rationales and writes briefs
and answers from the facts MARLOW gathered. It is given only those facts and is
told it may not invent any, and its output is labeled as narration. Without a key,
the same documents are produced from templates, so MARLOW is fully useful with no
model at all. The model never chooses an action.
"""
from __future__ import annotations

import datetime as dt
import logging

from .config import settings

log = logging.getLogger(__name__)

_BASE = (
    "You are MARLOW, the operations brain of Vendetta Cyber, a digital forensics and incident "
    "response firm. Write direct declarative prose in short paragraphs. Use only the facts provided; "
    "never invent a finding, a number, a name or a date. If a fact is missing say so plainly. No em "
    "dashes, no bullet-point dumps, no hedging filler. Never recommend an action on a client host; a "
    "human responder decides those."
)

# Internal voice: for the team only.
_PERSONA = {
    "marlow": (
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
    return _BASE + _PERSONA.get(settings.persona, _PERSONA["marlow"])


def enabled() -> bool:
    return bool((settings.anthropic_api_key or "").strip())


def _complete(prompt: str, max_tokens: int = 900, audience: str = "internal") -> str | None:
    if not enabled():
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        msg = client.messages.create(model=settings.llm_model, max_tokens=max_tokens, system=system(audience),
                                     messages=[{"role": "user", "content": prompt}])
        return "".join(getattr(b, "text", "") for b in msg.content).strip() or None
    except Exception as e:  # noqa: BLE001
        log.warning("narrative: model call failed (%s); using template", type(e).__name__)
        return None


def client_brief(client: dict, findings: list[dict], cases: list[dict]) -> tuple[str, str]:
    """Returns (markdown, source)."""
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
                        "opened": c.get("opened_at"), "lead": c.get("lead")} for c in cases],
    }
    text = _complete(
        "Write a one-page posture brief for the client's leadership from these facts. Open with where they "
        "stand in two sentences, then what is being handled, then what they should do this week. "
        f"Facts (JSON): {facts}", audience="client")
    if text:
        return f"# {name}: security posture brief\n\n_{today}, prepared by MARLOW_\n\n" + text, "llm"
    lines = [f"# {name}: security posture brief", "", f"_{today}, prepared by MARLOW_", "", "## Where you stand", ""]
    if not findings and not cases:
        lines.append("Nothing is active for you across Vendetta's monitoring, response and testing services today.")
    else:
        sev = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda kv: -perception_rank(kv[0])))
        lines.append(f"{len(findings)} active findings ({sev}) and {len(cases)} open incident case(s).")
    if cases:
        lines += ["", "## Being handled", ""]
        for c in cases:
            lines.append(f"{c.get('number')}: {c.get('title')} ({c.get('severity')}), lead {c.get('lead') or 'Vendetta IR'}.")
    top = sorted(findings, key=lambda f: -perception_rank(f.get("severity", "low")))[:8]
    if top:
        lines += ["", "## Open findings", ""]
        for f in top:
            lines.append(f"{f.get('severity')}: {f.get('title')} ({f['_module'].replace('-', ' ')}, {f.get('status')}).")
    lines += ["", "## This week", "",
              "Your Vendetta account owner will walk through the items above and the remediation owed on each. "
              "Anything marked critical is being worked now."]
    return "\n".join(lines), "rules"


def daily_summary(stats: dict, proposals: list[dict], actions: list[dict]) -> tuple[str, str]:
    today = dt.date.today().isoformat()
    facts = {"date": today, "stats": stats, "proposals": proposals[:40], "actions": actions[:40]}
    text = _complete("Write the morning stand-up summary of what MARLOW observed, proposed and did in the last day, "
                     "and what is waiting on a person. Keep it to one screen. "
                     f"Facts (JSON): {facts}")
    if text:
        return f"# MARLOW daily summary, {today}\n\n" + text, "llm"
    opener = _greeting(stats) if settings.persona == "marlow" else ""
    lines = [f"# MARLOW daily summary, {today}", ""] + ([opener, ""] if opener else []) + ["## Queue", "",
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
    return "\n".join(lines), "rules"


def answer(question: str, picture: dict) -> tuple[str, str]:
    text = _complete(f"Answer the question from the platform picture. Question: {question}\n\nPicture (JSON): {picture}",
                     max_tokens=700)
    if text:
        return text, "llm"
    lead = "Nobody gave me a voice yet, so here is the picture without the charm: " if settings.persona == "marlow" \
        else "No language model is configured; the picture: "
    return (lead + f"{picture.get('open_items', 0)} open items, {picture.get('pending_proposals', 0)} proposals waiting on one of you, "
            f"{len(picture.get('clients', []))} clients, {len(picture.get('modules', {}))} modules in reach."
            + (" Set ANTHROPIC_API_KEY and I will do better than a count." if settings.persona == "marlow" else "")), "rules"


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
