"""Ask SABINE executes: a sentence becomes a skill call.

Two stages, both deterministic where it counts:

1. Which skill. A parser matches the sentence against each chat-capable skill's
   title, key and synonyms ("escalate", "re-sync", "close as false positive").
   When the narrative model is configured it is asked, first, for a structured
   intent (strict JSON, validated against the catalog); its answer only names the
   skill and the raw argument strings. Any failure or anything off-catalog falls
   back to the parser.
2. Which arguments. The same resolver runs either way, against the latest
   perception snapshot: a client by name or alias (case-insensitive, prefix), a
   finding by id or by "the <severity> on <client>", a case by number or by
   client, a module by key or common name, a person by first name from the staff
   roster. One match resolves; several make an ambiguity SABINE asks back about;
   none for a required input is an ambiguity too.

act() turns a resolved Intent into a Proposal through the normal reasoner path,
attributed in the ledger to ask:<user>, and lets the autonomy policy decide: auto
runs now, propose waits for a person, off is refused, and a high-risk skill never
runs from chat whatever the policy says.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import concierge, executor, ledger, memory, narrative, perception, policy, reach, reasoner, skills
from .config import settings
from .db import Proposal, WorkItem, utcnow

log = logging.getLogger(__name__)

THRESHOLD = 0.7
SEVERITIES = ("critical", "high", "medium", "low")
_GENERIC = {"the", "of", "and", "inc", "llc", "ltd", "co", "credit", "union", "bank", "group", "college", "university",
            "county", "city", "corp", "corporation", "company", "services", "service", "health", "point", "trust"}
_MODULE_WORDS = {
    "dark-web-monitoring": ("dark web", "darkweb", "dark-web-monitoring", "dwm"),
    "managed-services": ("managed services", "managed-services", "msp", "soc module"),
    "vulnerability-management": ("vulnerability", "vuln", "vulnerability-management"),
    "penetration-testing": ("pentest", "penetration", "penetration-testing"),
    "incident-response": ("incident response", "incident-response", "ir hub", "the hub"),
    "professional-services": ("professional services", "professional-services", "osp", "special projects"),
    "platform": ("platform", "control plane"),
    "mdr": ("mdr", "managed detection", "detection and response", "investigation"),
}
_CASE_RE = re.compile(r"\b(?:[A-Z]{2,5}-)?IR-\d{4}-\d{1,6}\b", re.I)


@dataclass
class Intent:
    utterance: str
    skill: skills.Skill | None = None
    args: dict = field(default_factory=dict)
    confidence: float = 0.0
    ambiguities: list[dict] = field(default_factory=list)   # {field, question, candidates: [{id, label}]}
    source: str = "parser"

    @property
    def actionable(self) -> bool:
        return self.skill is not None and self.confidence >= THRESHOLD and not self.ambiguities

    def as_dict(self) -> dict:
        return {"skill": self.skill.key if self.skill else None, "args": self.args, "confidence": self.confidence,
                "ambiguities": self.ambiguities, "source": self.source}


# ---------------------------------------------------------------- text helpers
def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower().replace("_", " ")).strip()


def _tokens(s: str) -> list[str]:
    return [t.strip(".,;:!?\"'()") for t in re.findall(r"[A-Za-z0-9@._'\-]+", s or "")]


def _contains(hay: str, phrase: str) -> bool:
    return re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", hay) is not None


# ---------------------------------------------------------------- which skill
def match_skill(utterance: str) -> tuple[skills.Skill | None, float]:
    """The chat skill whose longest phrase appears in the sentence."""
    text = _norm(utterance)
    best, best_len = None, 0
    for s in skills.chat_skills():
        for phrase in (*s.synonyms, s.title.lower(), s.key.replace("_", " ")):
            phrase = _norm(phrase)
            if len(phrase) > best_len and _contains(text, phrase):
                best, best_len = s, len(phrase)
    if best is None:
        return None, 0.0
    return best, 0.9


# ---------------------------------------------------------------- which arguments
def resolve_client(db: Session, text: str) -> tuple[dict | None, list[dict]]:
    """(client, candidates). Full name wins; otherwise a token of the sentence that
    equals or prefixes a distinctive word of the client's name."""
    low = _norm(text)
    toks = [t.lower() for t in _tokens(text) if len(t) >= 3]
    clients = perception.clients(db)
    full = [c for c in clients if c.get("name") and _contains(low, _norm(c["name"]))]
    if len(full) == 1:
        return full[0], []
    hits = []
    for c in clients:
        words = [w for w in _norm(c.get("name", "")).split() if w not in _GENERIC and len(w) >= 3]
        if any(t == w or (len(t) >= 4 and w.startswith(t)) for w in words for t in toks):
            hits.append(c)
    if len(hits) == 1:
        return hits[0], []
    return None, [{"id": c["id"], "label": c["name"]} for c in (hits or full)]


def _client_of(f: dict) -> tuple[str, str]:
    subj = f.get("subject") or {}
    return subj.get("client") or "", subj.get("platform_client_id") or ""


def resolve_finding(db: Session, text: str, module: str | None = None) -> tuple[dict | None, list[dict]]:
    """A finding by id, by host, or by severity and client. Several matches: the
    newest when the sentence says so, otherwise candidates for SABINE to ask about."""
    module = module or resolve_module(text)[0]
    rows = [f for f in perception.findings(db) if not module or f["_module"] == module]
    toks = {t.lower() for t in _tokens(text)}
    by_id = [f for f in rows if str(f.get("id", "")).lower() in toks]
    if len(by_id) == 1:
        return by_id[0], []
    by_host = [f for f in rows if (f.get("matched") or "").lower() in toks and f.get("matched")]
    if len(by_host) == 1:
        return by_host[0], []
    low = _norm(text)
    sev = next((s for s in SEVERITIES if _contains(low, s)), None)
    client, _ = resolve_client(db, text)
    pool = by_id or by_host or rows
    if sev:
        pool = [f for f in pool if f.get("severity") == sev]
    if client:
        pool = [f for f in pool if _client_of(f)[1] == client["id"] or _client_of(f)[0] == client["name"]]
    if not (sev or client or by_id or by_host):
        return None, []
    if len(pool) == 1:
        return pool[0], []
    if pool and any(w in low for w in ("latest", "newest", "most recent")):
        return sorted(pool, key=lambda f: f.get("created_at") or "", reverse=True)[0], []
    return None, [{"id": f["id"], "label": f"{f['id']}: {f.get('severity')} {f.get('title', '')} ({_client_of(f)[0]}, {f['_module']})"}
                  for f in sorted(pool, key=lambda f: f.get("created_at") or "", reverse=True)[:8]]


def resolve_case(db: Session, text: str) -> tuple[dict | None, list[dict]]:
    cases = perception.cases(db)
    m = _CASE_RE.search(text or "")
    if m:
        num = m.group(0).upper()
        hit = [c for c in cases if (c.get("number") or "").upper().endswith(num)]
        if len(hit) == 1:
            return hit[0], []
    client, _ = resolve_client(db, text)
    if client:
        pool = [c for c in cases if (c.get("client") or {}).get("platform_client_id") == client["id"]
                or (c.get("client") or {}).get("name") == client["name"]]
        if len(pool) == 1:
            return pool[0], []
        return None, [{"id": c["id"], "label": f"{c.get('number')}: {c.get('title')}"} for c in pool]
    return None, [{"id": c["id"], "label": f"{c.get('number')}: {c.get('title')} ({(c.get('client') or {}).get('name', '')})"} for c in cases[:8]]


def resolve_module(text: str) -> tuple[str | None, list[dict]]:
    low = _norm(text)
    known = set(reach.directory()) | set(_MODULE_WORDS)
    hits = [k for k in known if _contains(low, k) or any(_contains(low, w) for w in _MODULE_WORDS.get(k, ()))]
    if len(hits) == 1:
        return hits[0], []
    return None, [{"id": k, "label": k} for k in sorted(hits)]


def resolve_person(db: Session, text: str, user: str = "") -> dict | None:
    """A staff member by first name (or "me")."""
    toks = {t.lower() for t in _tokens(text)}
    people = [p for p in (perception.staff(db).get("staff") or []) if p.get("active", True)]
    if "me" in toks and user:
        return {"email": user, "name": user.split("@")[0].split(".")[0].capitalize()}
    for p in people:
        first = ((p.get("name") or "").split() or [p.get("email", "").split("@")[0].split(".")[0]])[0].lower()
        if first and first in toks and first not in _GENERIC:
            return {"email": p["email"], "name": p.get("name") or p["email"]}
    return None


def resolve_args(db: Session, skill: skills.Skill, text: str, user: str = "") -> tuple[dict, list[dict]]:
    """Resolve every input the skill declares from the text. Missing required
    inputs and multiple matches become ambiguities."""
    args: dict = {}
    amb: list[dict] = []
    for inp in skill.inputs:
        if inp.type == "finding_id":
            hint = "managed-services" if skill.key == "host_action" else "mdr" if skill.key == "suggest_suppression" else None
            f, cands = resolve_finding(db, text, hint)
            if f:
                args["finding_id"], args["finding"] = f["id"], f
            elif inp.required:
                amb.append({"field": "finding_id", "candidates": cands,
                            "question": "Which finding? Give me its id, or the severity and the client." if not cands
                            else "I see more than one finding that fits. Which one?"})
        elif inp.type == "client":
            c, cands = resolve_client(db, text)
            if c:
                args["client"] = c
            elif inp.required:
                amb.append({"field": "client", "candidates": cands or [{"id": x["id"], "label": x["name"]} for x in perception.clients(db)[:8]],
                            "question": "Which client?" if not cands else "That could be more than one client. Which?"})
        elif inp.type == "case":
            c, cands = resolve_case(db, text)
            if c:
                args["case"] = c
            elif inp.required:
                amb.append({"field": "case", "candidates": cands,
                            "question": "Which case? A number or the client will do." if not cands else "More than one open case fits. Which?"})
        elif inp.type == "module":
            m, cands = resolve_module(text)
            if m:
                args["module"] = m
            elif inp.required:
                amb.append({"field": "module", "candidates": cands or [{"id": k, "label": k} for k in sorted(reach.directory())],
                            "question": "Which module?"})
        elif inp.type == "host":
            f = args.get("finding")
            if f and f.get("matched"):
                args["host"] = f["matched"]
        elif inp.type == "person":
            p = resolve_person(db, text, user)
            if p:
                args["person"] = p
    # A person named alongside any skill is told about the outcome.
    if "person" not in args:
        p = resolve_person(db, text, user)
        if p:
            args["person"] = p
    return args, amb


# ---------------------------------------------------------------- parse
def parse(db: Session, utterance: str, user: str = "") -> Intent:
    utterance = (utterance or "").strip()
    hint = _model_hint(utterance) if narrative.enabled() else None
    if hint:
        skill = skills.REGISTRY.get(hint.get("skill") or "")
        if skill and skill.chat:
            text = " ".join(str(v) for k, v in hint.items() if k != "skill" and v)
            args, amb = resolve_args(db, skill, f"{utterance} {text}", user)
            return Intent(utterance, skill, args, 0.9, amb, source="llm")
        if skill is None and hint.get("skill") is None and hint.get("question") is True:
            return Intent(utterance, None, {}, 0.0, [], source="llm")
    skill, conf = match_skill(utterance)
    if skill is None:
        return Intent(utterance)
    args, amb = resolve_args(db, skill, utterance, user)
    return Intent(utterance, skill, args, conf, amb)


def _model_hint(utterance: str) -> dict | None:
    """Ask the model for a structured intent only. Anything that fails to parse or
    names a skill off the catalog is discarded."""
    catalog = [{"skill": s.key, "title": s.title, "synonyms": list(s.synonyms), "inputs": [i.name for i in s.inputs]}
               for s in skills.chat_skills()]
    prompt = ("Extract the intent of this sentence as JSON only, no prose. Schema: {\"skill\": <one of the skill keys "
              "or null>, \"question\": <true when the sentence is a question and not a request to act>, "
              "\"finding_id\": <string or null>, \"client\": <string or null>, \"person\": <string or null>, "
              "\"module\": <string or null>, \"case\": <string or null>, \"severity\": <string or null>}. "
              "Copy argument values verbatim from the sentence; never invent one.\n"
              f"Skills: {json.dumps(catalog)}\nSentence: {utterance}")
    raw = narrative.extract(prompt)
    if not raw:
        return None
    try:
        m = re.search(r"\{.*\}", raw, re.S)
        data = json.loads(m.group(0) if m else raw)
    except (ValueError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    allowed = {"skill", "question", "finding_id", "client", "person", "module", "case", "severity"}
    data = {k: v for k, v in data.items() if k in allowed}
    if data.get("skill") is not None and data["skill"] not in skills.REGISTRY:
        return None
    return data


# ---------------------------------------------------------------- act
def _asked(user: str) -> str:
    first = user.split("@")[0].split(".")[0].capitalize() if user else "Someone"
    return first


def build(db: Session, intent: Intent, user: str) -> dict:
    """The proposal fields for a resolved intent: key, title, rationale, facts,
    target, confidence. Keys match the ones the rules use for the same target so
    the usual dedupe applies."""
    s, a, u = intent.skill, intent.args, intent.utterance
    who = _asked(user)
    lead = f"{who} asked on the Ask page: \"{u[:200]}\". "
    base = {"source": "ask", "by": user, "utterance": u[:500]}
    if a.get("person"):
        base["notify"] = a["person"]["email"]
    f = a.get("finding") or {}
    client_name, cid = _client_of(f) if f else ("", "")
    mod = f.get("_module", "")
    if s.key == "escalate_finding":
        return dict(key=f"escalate_finding:{mod}:{f['id']}",
                    title=f"Escalate {f.get('severity')} {mod.replace('-', ' ')} finding for {client_name or 'unknown client'}",
                    rationale=lead + f"The {f.get('severity')} finding \"{f.get('title', '')}\" in {mod} has no IR case; escalating opens or links one in the hub.",
                    facts={**base, "module": mod, "finding_id": f["id"], "severity": f.get("severity"), "title": f.get("title"),
                           "client": client_name, "platform_client_id": cid},
                    target={"module": mod, "id": f["id"], "path": f"/api/findings/{f['id']}/escalate"}, confidence=0.9)
    if s.key == "copilot_false_positive":
        cp = f.get("copilot") or {}
        link = (reach.public_url(mod) + perception.FINDING_PATH[mod].format(id=f["id"])) if reach.public_url(mod) and mod in perception.FINDING_PATH else ""
        return dict(key=f"copilot_false_positive:{mod}:{f['id']}",
                    title=f"Confirm and close as false positive: {f.get('title', '')}"[:400],
                    rationale=lead + f"A responder should confirm the call and close it in {mod}, where closing needs a second approver."
                    + (f" The module's copilot agrees at {float(cp.get('confidence') or 0):.0%}." if cp.get("verdict") == "false_positive" else ""),
                    facts={**base, "module": mod, "finding_id": f["id"], "severity": f.get("severity"), "title": f.get("title"),
                           "client": client_name, "platform_client_id": cid},
                    target={"kind": "copilot_fp", "severity": "low", "client": client_name, "platform_client_id": cid, "link": link},
                    confidence=0.85)
    if s.key == "host_action":
        host = a.get("host") or f.get("matched") or "the affected host"
        return dict(key=f"host_action:{f['id']}", title=f"Consider isolating {host} ({client_name})",
                    rationale=lead + f"A {f.get('severity')} {f.get('type', 'alert')} is active on {host} for {client_name}: \"{f.get('title', '')}\". "
                    "SABINE does not touch hosts. A responder with the act grant decides in managed services, where the second-person control applies.",
                    facts={**base, "module": "managed-services", "finding_id": f["id"], "host": host, "client": client_name, "type": f.get("type")},
                    target={"module": "managed-services", "id": f["id"],
                            "link": (reach.public_url("managed-services") + f"/alerts/{f['id']}") if reach.public_url("managed-services") else ""},
                    confidence=0.7)
    if s.key == "link_related_findings":
        c = a["client"]
        rows = [x for x in perception.findings(db) if _client_of(x)[1] == c["id"]]
        return dict(key=f"correlate:{c['id']}:ask", title=f"Related findings for {c['name']}",
                    rationale=lead + f"{c['name']} has {len(rows)} active findings across {len({x['_module'] for x in rows}) or 0} modules; the responder should read them as one story.",
                    facts={**base, "client": c["name"], "platform_client_id": c["id"], "finding_ids": [x["id"] for x in rows],
                           "modules": sorted({x["_module"] for x in rows})},
                    target={"kind": "correlation", "client": c["name"], "platform_client_id": c["id"],
                            "severity": max((x.get("severity", "low") for x in rows), key=lambda v: perception.SEV_RANK.get(v, 0), default="medium")},
                    confidence=0.8)
    if s.key == "roster_sync":
        m = a["module"]
        return dict(key=f"roster_sync:{m}", title=f"Re-sync {m} roster",
                    rationale=lead + f"SABINE will ask {m} to pull its roster from the platform again.",
                    facts={**base, "module": m}, target={"module": m, "path": "/api/provision/sync"}, confidence=0.9)
    if s.key == "stale_case_nudge":
        c = a["case"]
        name = (c.get("client") or {}).get("name", "")
        return dict(key=f"stale_case:{c['id']}", title=f"Nudge {c.get('number')} ({name})",
                    rationale=lead + f"Case {c.get('number')} ({name}, {c.get('severity')}), lead {c.get('lead') or 'unassigned'}, is raised to its lead with what is outstanding.",
                    facts={**base, "case": c.get("number"), "client": name, "lead": c.get("lead")},
                    target={"kind": "nudge", "severity": "medium", "client": name,
                            "platform_client_id": (c.get("client") or {}).get("platform_client_id", ""),
                            "link": (reach.public_url("incident-response") + f"/cases/{c['id']}") if reach.public_url("incident-response") else ""},
                    confidence=0.85)
    if s.key == "client_brief":
        c = a["client"]
        return dict(key=f"client_brief:{c['id']}:ask:{utcnow():%Y%m%d%H%M}", title=f"Brief for {c['name']}",
                    rationale=lead + f"A current posture brief for {c['name']} is written for the account owner to send.",
                    facts={**base, "client": c["name"], "platform_client_id": c["id"]},
                    target={"kind": "brief", "client": c["name"], "platform_client_id": c["id"]}, confidence=0.95)
    if s.key == "page_oncall":
        ref = f"{mod}:{f['id']}"
        link = (reach.public_url(mod) + perception.FINDING_PATH[mod].format(id=f["id"])) if reach.public_url(mod) and mod in perception.FINDING_PATH else ""
        title = f"Page on-call: {f.get('severity')} {mod.replace('-', ' ')} detection for {client_name or 'unknown client'}"
        body = f"{who} asked SABINE to page the on-call responder for \"{f.get('title', '')}\" ({f.get('severity')}) on {client_name or 'an unknown client'}."
        return dict(key=f"page_oncall:{ref}", title=title,
                    rationale=lead + "SABINE pages the on-call responder through the IR hub.",
                    facts={**base, "module": mod, "finding_id": f["id"], "severity": f.get("severity"), "title": f.get("title"),
                           "client": client_name, "platform_client_id": cid},
                    target={"module": "incident-response", "path": "/api/oncall/page", "platform_client_id": cid, "client": client_name,
                            "link": link, "body": {"title": concierge.page_title(title), "body": body, "link": link,
                                                   "severity": f.get("severity"), "platform_client_id": cid, "client": client_name,
                                                   "source_module": mod, "source_ref": f["id"]}},
                    confidence=0.9)
    if s.key == "suggest_suppression":
        sig = memory.signature(f.get("title") or "")
        h = memory.noise(db).get((cid, sig), {"false_positive": 0, "rejected": 0})
        phrase = f.get("title") or ""
        return dict(key=f"suggest_suppression:{cid}:{memory.sig_hash(sig)}",
                    title=f"Suppress \"{phrase}\" for {client_name} for {settings.suppression_days} days"[:400],
                    rationale=lead + (f"People have called this pattern noise for {client_name} {h['false_positive'] + h['rejected']} "
                                      f"time(s) so far. A {settings.suppression_days}-day MDR suppression for this client only "
                                      "needs a person's approval."),
                    facts={**base, "module": mod, "finding_id": f["id"], "title": phrase, "client": client_name,
                           "platform_client_id": cid, "signature": sig, "false_positive": h["false_positive"], "rejected": h["rejected"]},
                    target={"module": "mdr", "path": "/api/suppressions", "platform_client_id": cid, "client": client_name,
                            "title_contains": phrase, "days": settings.suppression_days,
                            "reason": f"Asked for by {user or 'a person'} on the Ask page"},
                    confidence=0.6)
    if s.key == "posture_review":
        c = a["client"]
        month = utcnow().strftime("%Y-%m")
        return dict(key=f"posture_review:{c['id']}:{month}", title=f"Posture review for {c['name']}, {utcnow():%B %Y}",
                    rationale=lead + f"SABINE drafts the {utcnow():%B %Y} posture review for {c['name']} on the platform; the account lead approves it.",
                    facts={**base, "client": c["name"], "platform_client_id": c["id"], "month": month, "source_ref": f"review:{c['id']}:{month}"},
                    target={"kind": "posture_review", "platform_client_id": c["id"], "client": c["name"], "month": month,
                            "source_ref": f"review:{c['id']}:{month}"},
                    confidence=0.95)
    if s.key == "client_outreach":
        c = a["client"]
        stamp = f"{utcnow():%Y%m%d%H%M}"
        rows = [x for x in perception.findings(db) if _client_of(x)[1] == c["id"]]
        msg = (f"We wanted to give you a short update. Your Vendetta team is watching {len(rows)} active item(s) for you "
               "today and will walk through them with you." if rows else
               "We wanted to give you a short update: nothing is active for you across our services today, and we keep watching.")
        return dict(key=f"client_outreach:ask:{c['id']}:{stamp}", title=f"Outreach to {c['name']}: a note from your Vendetta team",
                    rationale=lead + f"SABINE drafts an email to {c['name']} on the platform; a person approves it and it sends.",
                    facts={**base, "client": c["name"], "platform_client_id": c["id"], "reason": "check_in", "message": msg,
                           "source_ref": f"ask:{c['id']}:{stamp}"},
                    target={"kind": "outreach", "platform_client_id": c["id"], "client": c["name"], "reason": "check_in",
                            "source_ref": f"ask:{c['id']}:{stamp}"},
                    confidence=0.85)
    if s.key == "daily_summary":
        return dict(key=f"daily_summary:ask:{utcnow():%Y%m%d%H%M}", title="Daily summary",
                    rationale=lead + "The day's observations, proposals, decisions and actions, written now.",
                    facts=base, target={"kind": "summary"}, confidence=1.0)
    raise KeyError(f"{s.key} cannot be built from chat")


def act(db: Session, intent: Intent, user: str) -> dict:
    """Carry a resolved intent through the autonomy engine. Returns
    {kind, reply, proposal, result} where kind is one of done, failed, pending,
    high, off, already_pending, already_done."""
    s = intent.skill
    spec = build(db, intent, user)
    # The client's own override applies when the request targets one client.
    pid = (spec.get("target") or {}).get("platform_client_id") or (spec.get("facts") or {}).get("platform_client_id") or None
    level = policy.autonomy(db, s.key, pid)
    if level == "off":
        return {"kind": "off", "reply": narrative.ask_reply("off", skill=s), "proposal": None}
    prior = reasoner._pending(db, spec["key"])
    if prior is not None and prior.status in ("pending", "approved"):
        return {"kind": "already_pending", "reply": narrative.ask_reply("already_pending", skill=s, proposal=prior), "proposal": prior}
    if prior is not None and prior.status == "executed" and prior.executed_at and (utcnow() - prior.executed_at) < dt.timedelta(hours=24):
        return {"kind": "already_done", "reply": narrative.ask_reply("already_done", skill=s, proposal=prior), "proposal": prior}
    p = reasoner.propose(db, s.key, spec["key"], spec["title"], spec["rationale"], spec["facts"], spec["target"], spec["confidence"])
    if p is None:
        return {"kind": "off", "reply": narrative.ask_reply("off", skill=s), "proposal": None}
    db.commit()
    ledger.append(db, "proposal", f"ask:{user}", f"{p.action}: {p.title}",
                  {"facts": p.facts, "target": p.target, "confidence": p.confidence, "risk": p.risk, "autonomy": p.autonomy,
                   "rationale": p.rationale, "source": "ask", "intent": intent.as_dict() | {"args": _plain_args(intent.args)}}, ref=p.id)
    person = intent.args.get("person")
    if s.risk == "high":
        # Never from chat, whatever the policy row says: a person with the grant approves it.
        return {"kind": "high", "reply": narrative.ask_reply("high", skill=s, proposal=p), "proposal": p}
    if p.autonomy != "auto":
        return {"kind": "pending", "reply": narrative.ask_reply("pending", skill=s, proposal=p), "proposal": p}
    res = executor.execute(db, p)
    ledger.append(db, "action", settings.actor_name, f"{p.action} {'done' if res.get('ok') else 'failed'}: {p.title}",
                  {"result": res, "autonomy": "auto", "action": p.action, "asked_by": user}, ref=p.id)
    if res.get("ok") and person and person["email"] != user:
        _nudge(db, p, person)
    kind = "done" if res.get("ok") else "failed"
    return {"kind": kind, "reply": narrative.ask_reply(kind, skill=s, proposal=p, result=res, person=person), "proposal": p, "result": res}


def _nudge(db: Session, p: Proposal, person: dict) -> None:
    """A queue item claimed by the person named in the sentence, so the outcome lands on their desk."""
    key = f"sabine:nudge:{p.id}"
    if db.execute(select(WorkItem).where(WorkItem.key == key)).scalar_one_or_none():
        return
    db.add(WorkItem(key=key, source="sabine", kind="nudge", domain=p.domain, title=f"For {person['name'].split()[0]}: {p.title}"[:400],
                    client=p.facts.get("client") or "", platform_client_id=p.facts.get("platform_client_id") or "",
                    severity="medium", state="claimed", owner=person["email"], link=(p.target or {}).get("link", ""),
                    payload={"proposal": p.id, "rationale": p.rationale, "facts": p.facts}))
    db.commit()


def _plain_args(args: dict) -> dict:
    out = {}
    for k, v in args.items():
        if k == "finding":
            out["finding"] = {"id": v.get("id"), "module": v.get("_module"), "title": v.get("title")}
        elif k == "case":
            out["case"] = v.get("number")
        elif k == "client":
            out["client"] = v.get("name")
        else:
            out[k] = v
    return out


def clarify(intent: Intent) -> str:
    return narrative.ask_clarify(intent)
