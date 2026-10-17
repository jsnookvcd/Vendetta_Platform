"""Watch term matching. Runs over every new item and creates Hits.

Term kinds:
  domain        exact host or any subdomain, case insensitive (acme.com matches mail.acme.com)
  email_domain  any address at that domain
  keyword       whole word, case insensitive
  brand         like keyword but also matches with spaces removed (Acme Corp -> acmecorp)
  person        full name, case insensitive, tolerant of middle initials being absent
  regex         raw regex, case insensitive
  ip_cidr       any IPv4 inside the CIDR
"""
from __future__ import annotations

import ipaddress
import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Client, Hit, Item, WatchTerm

log = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _compile(term: WatchTerm) -> re.Pattern | None:
    t = term.term.strip()
    if not t:
        return None
    esc = re.escape(t)
    if term.kind == "domain":
        return re.compile(rf"(?<![\w.-])(?:[\w-]+\.)*{esc}(?![\w-])", re.I)
    if term.kind == "email_domain":
        return re.compile(rf"[\w.+-]+@(?:[\w-]+\.)*{esc}(?![\w-])", re.I)
    if term.kind == "keyword":
        return re.compile(rf"\b{esc}\b", re.I)
    if term.kind == "brand":
        squashed = re.escape(re.sub(r"\s+", "", t))
        return re.compile(rf"\b(?:{esc}|{squashed})\b", re.I)
    if term.kind == "person":
        parts = [re.escape(p) for p in t.split()]
        if len(parts) >= 2:
            return re.compile(rf"\b{parts[0]}\s+(?:\w+\.?\s+)?{parts[-1]}\b", re.I)
        return re.compile(rf"\b{esc}\b", re.I)
    if term.kind == "regex":
        try:
            return re.compile(t, re.I)
        except re.error as e:
            log.warning("bad regex term %s: %s", t, e)
            return None
    return None


def _match_cidr(term: WatchTerm, text: str) -> str | None:
    try:
        net = ipaddress.ip_network(term.term.strip(), strict=False)
    except ValueError:
        return None
    for m in IPV4_RE.finditer(text):
        try:
            if ipaddress.ip_address(m.group(0)) in net:
                return m.group(0)
        except ValueError:
            continue
    return None


def match_item(db: Session, item: Item, terms: list[WatchTerm] | None = None) -> list[Hit]:
    """Match one item. `terms` limits matching to those rows (a backfill for one
    client or for newly added terms); by default every enabled term of every
    active client is used."""
    text = f"{item.title}\n{item.body}\n{item.url}"
    if terms is None:
        terms = db.execute(
            select(WatchTerm).join(Client).where(WatchTerm.enabled.is_(True), Client.active.is_(True))
        ).scalars().all()
    created: list[Hit] = []
    for term in terms:
        matched: str | None = None
        if term.kind == "ip_cidr":
            matched = _match_cidr(term, text)
        else:
            pat = _compile(term)
            if pat:
                m = pat.search(text)
                matched = m.group(0) if m else None
        if not matched:
            continue
        # A domain/email-domain match inside credential-bearing content is a
        # credential exposure, not just a mention. Flag the reason and keep the
        # stored snippet redacted (the item body was already masked at ingest).
        reason = "term"
        if term.kind in ("domain", "email_domain") and item.kind in ("paste", "stealer", "credential", "message"):
            reason = "credential"
        exists = db.execute(
            select(Hit.id).where(
                Hit.client_id == term.client_id, Hit.item_id == item.id, Hit.term_id == term.id, Hit.reason == reason
            )
        ).first()
        if exists:
            continue
        sev = term.severity
        # A victim/post naming the client, or a live credential, is at least high.
        if item.kind in ("victim", "post") and sev in ("low", "medium"):
            sev = "high"
        if item.kind == "stealer" and sev in ("low", "medium"):
            sev = "high"
        hit = Hit(client_id=term.client_id, item_id=item.id, term_id=term.id, reason=reason, matched_text=matched[:500], severity=sev)
        db.add(hit)
        created.append(hit)
    if created:
        db.commit()
    return created
