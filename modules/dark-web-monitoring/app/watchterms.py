"""Starter watch terms for provisioned clients (recovery plan F7).

A client provisioned from the control plane used to arrive with no watch terms,
so nothing could ever hit. Provisioning now calls ensure_starter_terms() for every
client it creates or updates. It adds, when missing:

  - each portal domain as a `domain` term and an `email_domain` term;
  - the client name as a `brand` term, plus a second `brand` variant with common
    legal suffixes stripped (Riverbend Credit Union -> Riverbend).

These rows carry source="auto". The rules that keep analysts in control:

  - an existing term with the same kind and text (any source, enabled or not) is
    left exactly as it is, so an analyst's term is never altered;
  - provisioning never deletes a term;
  - when an analyst removes an auto term, record_deletion() writes a tombstone and
    provisioning never adds that term and kind for that client again.

Brand terms shorter than MIN_BRAND_LEN or made only of generic words (STOPWORDS)
are skipped because they would match unrelated victims and posts."""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AutoTermTombstone, Client, WatchTerm

AUTO, ANALYST = "auto", "analyst"
MIN_BRAND_LEN = 4
AUTO_SEVERITY = "medium"

# Longest first so "Federal Credit Union" is stripped before "Credit Union".
LEGAL_SUFFIXES = (
    "federal credit union", "credit union", "corporation", "l.l.c.", "n.a.",
    "llc", "inc", "corp", "ltd", "fcu", "bank", "co",
)

# Words that, on their own or only in combination with each other, appear in
# thousands of organization names. A brand term made only of these floods hits.
STOPWORDS = frozenset("""
the and of a an
first national american united community citizens peoples people's state
federal credit union bank banks trust savings financial finance capital
group holdings holding services service solutions systems partners global
international company companies associates enterprises industries
security secure home health healthcare medical care center centre
city county valley mountain river north south east west central
new great general standard premier alliance mutual
""".split())

_SUFFIX_RE = re.compile(
    r"[\s,]+(?:" + "|".join(re.escape(s).replace(r"\.", r"\.?") for s in LEGAL_SUFFIXES) + r")\.?\s*$",
    re.I,
)


def strip_suffixes(name: str) -> str:
    """Remove trailing legal suffixes, repeatedly: "First Bank, N.A." -> "First"."""
    out = (name or "").strip()
    while True:
        new = re.sub(r"(?:\s+(?:and|&))+$", "", _SUFFIX_RE.sub("", out), flags=re.I).strip(" ,.-&")
        if new == out or not new:
            return out
        out = new


def _generic(term: str) -> bool:
    words = re.findall(r"[a-z0-9']+", term.lower())
    return not words or all(w in STOPWORDS for w in words)


def usable_brand(term: str) -> bool:
    t = (term or "").strip()
    return len(t) >= MIN_BRAND_LEN and not _generic(t)


def _domains(raw: str) -> list[str]:
    out: list[str] = []
    for part in re.split(r"[,\s;]+", raw or ""):
        d = part.strip().lower().lstrip("@").rstrip(".")
        if d.startswith("www."):
            d = d[4:]
        if "." in d and re.fullmatch(r"[a-z0-9.-]+", d) and d not in out:
            out.append(d)
    return out


def starter_terms(name: str, portal_domains: str) -> list[tuple[str, str]]:
    """(term, kind) pairs a client with this name and these domains should have."""
    pairs: list[tuple[str, str]] = []
    for d in _domains(portal_domains):
        pairs += [(d, "domain"), (d, "email_domain")]
    # Trailing punctuation is dropped because the brand matcher anchors on word
    # boundaries; "Acme, Inc." would never match, "Acme, Inc" does.
    full = re.sub(r"\s+", " ", (name or "").strip()).rstrip(" .,")
    for brand in (full, strip_suffixes(full)):
        if usable_brand(brand) and (brand, "brand") not in pairs:
            pairs.append((brand, "brand"))
    return pairs


def _key(term: str, kind: str) -> tuple[str, str]:
    return kind, term.strip().lower()


def ensure_starter_terms(db: Session, client: Client) -> list[WatchTerm]:
    """Add the client's missing starter terms. Returns the rows added (flushed,
    not committed). Never alters or deletes an existing term."""
    if client.id is None:
        db.flush()
    existing = {_key(t.term, t.kind) for t in db.execute(
        select(WatchTerm).where(WatchTerm.client_id == client.id)).scalars()}
    tombstoned = {(k, t) for k, t in db.execute(
        select(AutoTermTombstone.kind, AutoTermTombstone.term).where(AutoTermTombstone.client_id == client.id)).all()}
    added: list[WatchTerm] = []
    for term, kind in starter_terms(client.name, client.portal_domains):
        key = _key(term, kind)
        if key in existing or key in tombstoned:
            continue
        wt = WatchTerm(client_id=client.id, term=term, kind=kind, severity=AUTO_SEVERITY, source=AUTO)
        db.add(wt)
        added.append(wt)
        existing.add(key)
    if added:
        db.flush()
    return added


def record_deletion(db: Session, term: WatchTerm, actor: str) -> None:
    """Called before an analyst deletes a term. Auto terms leave a tombstone so
    provisioning respects the removal; analyst terms need none."""
    if (term.source or ANALYST) != AUTO:
        return
    kind, text = _key(term.term, term.kind)
    exists = db.execute(select(AutoTermTombstone.id).where(
        AutoTermTombstone.client_id == term.client_id, AutoTermTombstone.kind == kind,
        AutoTermTombstone.term == text)).first()
    if not exists:
        db.add(AutoTermTombstone(client_id=term.client_id, term=text, kind=kind, deleted_by=actor[:320]))


def tombstones(db: Session, client_id: str) -> list[AutoTermTombstone]:
    return list(db.execute(select(AutoTermTombstone).where(AutoTermTombstone.client_id == client_id)
                           .order_by(AutoTermTombstone.deleted_at)).scalars())


def clients_without_terms(db: Session) -> list[Client]:
    """Active clients with zero enabled watch terms: they cannot produce a term hit."""
    has_terms = select(WatchTerm.client_id).where(WatchTerm.enabled.is_(True))
    return list(db.execute(select(Client).where(Client.active.is_(True), Client.id.not_in(has_terms))
                           .order_by(Client.name)).scalars())
