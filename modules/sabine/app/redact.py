"""Redaction for anything written to a client.

A client brief rests on facts SABINE gathered across the whole platform, so what
reaches the client is scrubbed of everything that is not theirs: other clients'
names, Vendetta's people (roster names, first names, internal addresses, the
leads named on cases and engagements), hostnames that are not the client's own,
links into the consoles, and anything that looks like a token.

redact_for_client(text, client, context) does the work; client_context(db,
client) builds the context from the perception snapshot. Without a context only
the generic rules run (links, tokens, internal addresses).
"""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from .config import settings

OTHER_CLIENT = "another client"
TEAM = "your Vendetta team"
HOST = "[host]"
TOKEN = "[redacted]"
_GENERIC_WORDS = {"the", "of", "and", "inc", "llc", "ltd", "co", "credit", "union", "bank", "group", "college", "university",
                  "county", "city", "corp", "corporation", "company", "services", "service", "health", "point", "trust"}
_URL = re.compile(r"https?://\S+")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I)
_TOKEN_KV = re.compile(r"\b(token|secret|password|api[_-]?key)\s*[=:]\s*\S+", re.I)
_LONG_HEX = re.compile(r"\b[0-9a-f]{32,}\b", re.I)
_DOTTED = re.compile(r"(?<![\w@.])([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?![\w@])", re.I)
_NETBIOS = re.compile(r"(?<![\w-])([A-Z]{2,15}[0-9]{1,4})(?![\w-])")  # WS01, SRV02; never a case number
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+\.)+[\w-]+\b")


def _words(name: str) -> list[str]:
    return [w for w in re.findall(r"[A-Za-z0-9']+", name or "") if w.lower() not in _GENERIC_WORDS and len(w) >= 3]


def client_context(db: Session, client: dict) -> dict:
    """Everything the redactor needs to know for one client: the other clients,
    Vendetta's people, and the client's own hosts and domains."""
    from . import perception

    cid, name = client.get("id", ""), client.get("name", "")
    others = [c["name"] for c in perception.clients(db) if c.get("name") and c.get("id") != cid and c["name"] != name]
    people: set[str] = set()
    for p in perception.staff(db).get("staff") or []:
        if p.get("name"):
            people.add(p["name"])
        if p.get("email"):
            people.add(p["email"])
    for c in perception.cases(db):
        if c.get("lead"):
            people.add(str(c["lead"]))
    for e in perception.engagements(db):
        if e.get("lead"):
            people.add(str(e["lead"]))
    own: set[str] = set()
    for f in perception.findings(db):
        subj = f.get("subject") or {}
        if subj.get("platform_client_id") == cid or subj.get("client") == name:
            m = (f.get("matched") or "").strip()
            if m:
                own.add(m.lower())
                if "@" in m:
                    own.add(m.split("@", 1)[1].lower())
    return {"others": others, "people": sorted(people), "own_hosts": own}


def redact_for_client(text: str, client: dict, context: dict | None = None) -> str:
    """Scrub text for one client's eyes."""
    if not text:
        return text
    ctx = context or {}
    name = client.get("name", "")
    own = {h.lower() for h in ctx.get("own_hosts") or ()}
    out = text
    # Links into the consoles and anything that looks like a credential.
    out = _URL.sub("[link]", out)
    out = _BEARER.sub(TOKEN, out)
    out = _TOKEN_KV.sub(lambda m: f"{m.group(1)} {TOKEN}", out)
    out = _LONG_HEX.sub(TOKEN, out)
    # Other clients: full names first, then their distinctive words.
    for other in sorted(ctx.get("others") or (), key=len, reverse=True):
        out = re.sub(re.escape(other), OTHER_CLIENT, out, flags=re.I)
        for w in _words(other):
            if w.lower() in {x.lower() for x in _words(name)}:
                continue
            out = re.sub(r"\b" + re.escape(w) + r"\b", OTHER_CLIENT, out, flags=re.I)
    # Vendetta's people: full names, first names, addresses.
    firsts: set[str] = set()
    for p in sorted(ctx.get("people") or (), key=len, reverse=True):
        if "@" in p:
            out = re.sub(re.escape(p), TEAM, out, flags=re.I)
            continue
        out = re.sub(r"\b" + re.escape(p) + r"\b", TEAM, out, flags=re.I)
        first = p.split()[0] if p.split() else ""
        if len(first) >= 3:
            firsts.add(first)
    for first in firsts:
        out = re.sub(r"\b" + re.escape(first) + r"\b", TEAM, out)
    domains = [d.strip().lower() for d in (settings.internal_email_domains or "").split(",") if d.strip()]

    def _email(m: re.Match) -> str:
        addr = m.group(0)
        dom = addr.split("@", 1)[1].lower()
        if dom in domains:
            return TEAM
        return addr if (addr.lower() in own or dom in own) else "[address]"
    out = _EMAIL.sub(_email, out)
    # Hostnames that are not the client's own.
    out = _DOTTED.sub(lambda m: m.group(0) if m.group(0).lower() in own or _looks_like_number_or_version(m.group(0)) else HOST, out)
    out = _NETBIOS.sub(lambda m: m.group(0) if m.group(0).lower() in own else HOST, out)
    out = re.sub(r"(\[host\])(?:,?\s*\[host\])+", r"\1", out)
    return out


def _looks_like_number_or_version(s: str) -> bool:
    """3.0.14, 10.2 and the like are versions, not hosts; so is a bare file suffix
    and an abbreviation such as a.m. or e.g."""
    if re.fullmatch(r"[0-9][0-9.]*", s) or re.fullmatch(r"[a-z0-9-]+\.(md|pdf|docx|txt|json|csv)", s, re.I):
        return True
    return all(len(part) <= 2 for part in s.split("."))


def redact_actions(actions: list[dict], client: dict, context: dict) -> list[dict]:
    return [{**a, "why": redact_for_client(a.get("why", ""), client, context),
             "what": redact_for_client(a.get("what", ""), client, context)} for a in actions]
