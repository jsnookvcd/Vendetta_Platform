"""Decision memory: what people decided before about the same thing.

A pattern is (skill, platform_client_id, signature), where the signature is the
finding or proposal title normalised so that numbers, ids and links do not make
two instances of one pattern look different ("Ransomware behavior on WS01" and
"... on WS07" share "ransomware behavior on ws#").

history() counts approvals and rejections among decided proposals for a pattern.
adjust() moves a new proposal's confidence by that history (each rejection
lowers it, each approval raises it, bounded) and returns the record propose()
writes into the proposal's facts, so the change is visible and auditable.

noise() feeds suggest_suppression: per (client, signature) of MDR detections, how
many times a person rejected SABINE's proposal on it and how many investigations
were closed as false positive in MDR. Each detection counts once per pattern: an
investigation closed as false positive and then rejected again in SABINE is one
piece of evidence, so a single detection never reaches the threshold alone.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings

LOOKBACK_DAYS = 180
MAX_DOWN = 0.5
MAX_UP = 0.2
APPROVED = ("approved", "executed", "failed")
# Proposals a person can reject about one MDR detection.
SOC_ON_FINDINGS = ("escalate_finding", "page_oncall", "host_action", "copilot_false_positive")


def signature(text: str) -> str:
    s = (text or "").lower()
    s = re.sub(r"https?://\S+", " ", s)
    s = re.sub(r"\b[0-9a-f]{12,}\b", "#", s)
    s = re.sub(r"\d+", "#", s)
    s = re.sub(r"#+", "#", s)
    s = re.sub(r"[^a-z#@.\- ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip(" .-")[:200]


def sig_hash(sig: str) -> str:
    return hashlib.sha1(sig.encode()).hexdigest()[:12]


def proposal_client(p) -> str:
    f, t = p.facts or {}, p.target or {}
    return str(f.get("platform_client_id") or t.get("platform_client_id") or "")


def proposal_signature(p) -> str:
    f = p.facts or {}
    return f.get("signature") or signature(f.get("title") or p.title)


def _decided(db: Session, actions: tuple[str, ...]):
    from .db import Proposal

    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=LOOKBACK_DAYS)
    q = select(Proposal).where(Proposal.action.in_(actions), Proposal.decided_at.is_not(None), Proposal.created_at >= since)
    return db.execute(q).scalars().all()


def history(db: Session, skill: str, pid: str, sig: str) -> dict:
    out = {"approved": 0, "rejected": 0}
    if not pid or not sig:
        return out
    for p in _decided(db, (skill,)):
        if proposal_client(p) != pid or proposal_signature(p) != sig:
            continue
        if p.status == "rejected":
            out["rejected"] += 1
        elif p.status in APPROVED:
            out["approved"] += 1
    return out


def adjust(db: Session, skill: str, pid: str, sig: str, confidence: float) -> tuple[float, dict | None]:
    """(new confidence, record or None when there is no history)."""
    h = history(db, skill, pid, sig)
    if not (h["approved"] or h["rejected"]):
        return confidence, None
    delta = settings.memory_approve_step * h["approved"] - settings.memory_reject_step * h["rejected"]
    delta = max(-MAX_DOWN, min(MAX_UP, delta))
    new = round(max(0.05, min(0.99, confidence + delta)), 3)
    return new, {"signature": sig, "approved": h["approved"], "rejected": h["rejected"], "base": round(confidence, 3),
                 "adjustment": round(new - confidence, 3)}


def noise(db: Session) -> dict[tuple[str, str], dict]:
    """{(pid, signature): {false_positive, rejected, titles, client, hosts}} for MDR
    detections, from MDR's closed investigations and people's rejections."""
    from . import perception

    out: dict[tuple[str, str], dict] = {}

    def slot(pid: str, sig: str, client: str) -> dict:
        return out.setdefault((pid, sig), {"false_positive": 0, "rejected": 0, "titles": [], "client": client,
                                           "hosts": set(), "tools": set(), "ids": set(),
                                           "missing_host": False, "missing_tool": False})

    def evidence(s: dict, host: str, tool: str) -> None:
        if host:
            s["hosts"].add(host)
        else:
            s["missing_host"] = True
        if tool:
            s["tools"].add(tool)
        else:
            s["missing_tool"] = True

    for f in perception.mdr_history(db):
        if (f.get("verdict") or "") != "false_positive":
            continue
        subj = f.get("subject") or {}
        pid = subj.get("platform_client_id") or ""
        if not pid:
            continue
        s = slot(pid, signature(f.get("title") or ""), subj.get("client") or "")
        fid = str(f.get("id") or "")
        if fid and fid in s["ids"]:
            continue
        s["ids"].add(fid)
        s["false_positive"] += 1
        # An MDR suppression matches the signal's title, never the investigation's
        # ("MDR-2026-0005: <rule> on <host>"), so the phrase comes from signal_title.
        s["titles"].append(f.get("signal_title") or f.get("title") or "")
        evidence(s, f.get("matched") or "", f.get("source_group") or "")
    for p in _decided(db, SOC_ON_FINDINGS):
        facts = p.facts or {}
        if p.status != "rejected" or facts.get("module") != "mdr":
            continue
        pid = proposal_client(p)
        if not pid:
            continue
        s = slot(pid, proposal_signature(p), facts.get("client") or "")
        # One detection is one piece of evidence, however many proposals on it were rejected.
        fid = str(facts.get("finding_id") or f"proposal:{p.id}")
        if fid in s["ids"]:
            continue
        s["ids"].add(fid)
        s["rejected"] += 1
        phrase = facts.get("signal_title") or facts.get("title")
        if phrase:
            s["titles"].append(phrase)
        evidence(s, facts.get("matched") or "", facts.get("source_group") or "")
    return out


def scope(h: dict) -> tuple[str, str]:
    """(tool, host) a suppression for a noise pattern can be narrowed to: each one
    only when every piece of evidence names it and they all agree, else ""."""
    tool = next(iter(h["tools"])) if len(h.get("tools") or ()) == 1 and not h.get("missing_tool") else ""
    host = next(iter(h["hosts"])) if len(h.get("hosts") or ()) == 1 and not h.get("missing_host") else ""
    return tool, host


def common_phrase(titles: list[str]) -> str:
    """The longest shared leading phrase of the titles, cut at a word boundary, for a
    suppression's title_contains. Falls back to the newest title."""
    titles = [t for t in titles if t]
    if not titles:
        return ""
    low = [t.lower() for t in titles]
    first = low[0]
    n = len(first)
    for t in low[1:]:
        i = 0
        while i < min(n, len(t)) and first[i] == t[i]:
            i += 1
        n = i
    phrase = titles[0][:n]
    if n < len(first) and " " in phrase:
        phrase = phrase.rsplit(" ", 1)[0]
    phrase = phrase.strip(" :-")
    return phrase if len(phrase) >= 8 else titles[-1]
