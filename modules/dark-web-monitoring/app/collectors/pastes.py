"""Paste site monitoring through psbdmp.ws, a free index of Pastebin dumps with a
search API. Each client domain and keyword term is searched; matching dumps are
pulled and stored. Pastebin's own scraping API needs a lifetime Pro account and
a whitelisted IP, which can be added later as a second source."""
from __future__ import annotations

import logging
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Client, Source, WatchTerm
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)
API = "https://psbdmp.ws/api/v3"


def _source(db: Session) -> Source:
    src = db.execute(select(Source).where(Source.kind == "paste")).scalar_one_or_none()
    if not src:
        src = Source(name="psbdmp paste index", kind="paste", url=API)
        db.add(src)
        db.commit()
    return src


def run(db: Session) -> None:
    src = _source(db)
    terms = db.execute(
        select(WatchTerm.term).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True), WatchTerm.kind.in_(("domain", "email_domain", "brand", "keyword")))
    ).scalars().all()
    try:
        for term in sorted(set(t.strip() for t in terms if len(t.strip()) >= 4)):
            r = httpx.get(f"{API}/search/{term}", timeout=30)
            if r.status_code != 200:
                continue
            data = r.json().get("data", []) if isinstance(r.json(), dict) else []
            for d in data[:50]:
                pid = d.get("id")
                if not pid:
                    continue
                body = ""
                dump = httpx.get(f"{API}/dump/{pid}", timeout=30)
                if dump.status_code == 200:
                    try:
                        body = dump.json().get("data", "")
                    except ValueError:
                        body = dump.text
                ingest(
                    db,
                    kind="paste",
                    title=f"Paste {pid} mentioning {term}",
                    body=(body or d.get("text") or "")[:100_000],
                    url=f"https://pastebin.com/{pid}",
                    external_id=f"psbdmp:{pid}",
                    group_name="pastebin",
                    source=src,
                    meta={"time": d.get("time"), "tags": d.get("tags")},
                    hash_parts=("paste", pid),
                )
                time.sleep(1)
            time.sleep(2)
        mark_source(db, src, True)
    except Exception as e:  # noqa: BLE001
        log.exception("paste run failed")
        mark_source(db, src, False, str(e))
