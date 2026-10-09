"""Certificate Transparency via crt.sh.

Two checks per client domain:
  1. New certificates issued for the domain or its subdomains. Unexpected subdomains
     are a common early signal of attacker infrastructure or shadow IT.
  2. Lookalike domains. A small set of permutations (homoglyph swaps, added hyphen,
     common TLD swaps, "secure-"/"login-" prefixes) is searched by identity. Any
     cert for a permutation is a potential phishing kit."""
from __future__ import annotations

import logging
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Client, Source, WatchTerm
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "rn": "m", "m": "rn", "vv": "w", "w": "vv"}
PREFIXES = ["secure-", "login-", "my-", "portal-", "mail-", "sso-"]
TLDS = [".net", ".org", ".co", ".io", ".app", ".info", ".us"]


def permutations(domain: str) -> list[str]:
    name, _, tld = domain.rpartition(".")
    if not name:
        return []
    out = set()
    for a, b in HOMOGLYPHS.items():
        if a in name:
            out.add(name.replace(a, b, 1) + "." + tld)
    for p in PREFIXES:
        out.add(f"{p}{name}.{tld}")
    for t in TLDS:
        if not domain.endswith(t):
            out.add(name + t)
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:] + "." + tld)
    out.discard(domain)
    return sorted(out)[:40]


def _crtsh(query: str) -> list[dict]:
    r = httpx.get("https://crt.sh/", params={"q": query, "output": "json"}, timeout=60)
    if r.status_code != 200 or not r.text.strip():
        return []
    try:
        return r.json()
    except ValueError:
        return []


def _source(db: Session) -> Source:
    src = db.execute(select(Source).where(Source.kind == "ct")).scalar_one_or_none()
    if not src:
        src = Source(name="crt.sh certificate transparency", kind="ct", url="https://crt.sh/")
        db.add(src)
        db.commit()
    return src


def run(db: Session) -> None:
    src = _source(db)
    rows = db.execute(
        select(WatchTerm, Client).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True), WatchTerm.kind == "domain")
    ).all()
    try:
        for term, client in rows:
            domain = term.term.strip().lower()
            # 1. New certs for the real domain
            for c in _crtsh(f"%.{domain}")[:500]:
                names = c.get("name_value", "")
                ingest(
                    db,
                    kind="cert",
                    title=f"Certificate for {names.splitlines()[0] if names else domain}",
                    body=f"Names:\n{names}\nIssuer: {c.get('issuer_name')}\nNot before: {c.get('not_before')}\nNot after: {c.get('not_after')}",
                    url=f"https://crt.sh/?id={c.get('id')}",
                    external_id=f"crt:{c.get('id')}",
                    group_name="ct",
                    source=src,
                    meta={"client_id": client.id, "domain": domain, "lookalike": False},
                    hash_parts=("cert", str(c.get("id"))),
                    preserve_on_hit=False,
                )
            time.sleep(2)
            # 2. Lookalikes. These are a separate item kind so a term match is not needed:
            #    we attach them to the client directly through a synthetic keyword match.
            for look in permutations(domain):
                certs = _crtsh(look)
                if not certs:
                    continue
                c = certs[0]
                ingest(
                    db,
                    kind="cert",
                    title=f"Lookalike domain certificate: {look} (resembles {domain})",
                    body=f"Lookalike: {look}\nTarget: {domain}\nIssuer: {c.get('issuer_name')}\nNot before: {c.get('not_before')}\nCerts seen: {len(certs)}",
                    url=f"https://crt.sh/?q={look}",
                    external_id=f"crt-look:{look}",
                    group_name="lookalike",
                    source=src,
                    meta={"client_id": client.id, "domain": domain, "lookalike": True},
                    hash_parts=("cert-look", look, str(len(certs))),
                    preserve_on_hit=False,
                )
                time.sleep(1.5)
        mark_source(db, src, True)
    except Exception as e:  # noqa: BLE001
        log.exception("ct run failed")
        mark_source(db, src, False, str(e))
