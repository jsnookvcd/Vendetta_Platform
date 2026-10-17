"""Paste site monitoring.

Each client domain, email domain, brand and keyword term is searched in a paste
index; matching pastes are pulled and stored as `paste` items, which the normal
pipeline matches and redacts.

The index sits behind the PasteSource interface below, so a replacement source is
one class plus an entry in SOURCES, selected with PASTE_SOURCE. The collector is
off unless PASTES_ENABLED is true.

psbdmp.ws status, checked Oct 17, 2026 (recovery plan Phase 4):
  - From the build sandbox, https://psbdmp.ws/api/v3/search/example.com could not
    be reached: the egress proxy refused the connection (HTTP 403 on CONNECT) and
    a WebFetch of the same URL was not permitted, so no live response was seen.
  - Web search found no current documentation for the psbdmp.ws v3 API. The most
    recent public reference found (an OSINT write-up from March 2024) describes
    the service at psbdmp.cc and says registration is required.
  - The recovery plan's local probe never confirmed it either (finding F8).
  The service is therefore treated as unreliable and PASTES_ENABLED defaults to
  false. To re-check from the deployed host, run `python -m app.diagnose` in the
  worker, which probes the psbdmp search URL, or Phase 0 block 4 of
  docs/dev/dark-web-recovery-plan.md. Set PASTES_ENABLED=true only after a probe
  returns HTTP 200 with JSON search results.

Pastebin's own scraping API needs a lifetime Pro account and a whitelisted IP; it
is the obvious replacement and would be written as a PasteSource."""
from __future__ import annotations

import dataclasses
import logging
import time
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Client, Source, WatchTerm
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)
API = "https://psbdmp.ws/api/v3"
MAX_RESULTS_PER_TERM = 50
DISABLED_REASON = ("PASTES_ENABLED is false: psbdmp.ws could not be verified as a working free API "
                   "(registration appears to be required); re-probe with python -m app.diagnose")


class SourceRefused(Exception):
    """The paste index answered with a non-success status for a search."""

    def __init__(self, status: int):
        super().__init__(f"HTTP {status}")
        self.status = status


@dataclasses.dataclass
class PasteHit:
    """One search result. `body` may be empty when the index only returns ids;
    the collector then asks the source for the full text with fetch()."""
    paste_id: str
    url: str
    body: str = ""
    meta: dict = dataclasses.field(default_factory=dict)


class PasteSource(Protocol):
    """What a paste index must provide. Implementations must be read only, send a
    clear User-Agent and raise SourceRefused on a refused search."""

    key: str          # value of PASTE_SOURCE that selects it
    name: str         # Source row name and Connectors page label
    url: str          # Source row url (unique per kind)

    def search(self, term: str) -> list[PasteHit]: ...

    def fetch(self, hit: PasteHit) -> str: ...


class PsbdmpSource:
    key = "psbdmp"
    name = "psbdmp paste index"
    url = API

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self._transport = transport

    def _get(self, path: str) -> httpx.Response:
        with httpx.Client(timeout=30, transport=self._transport) as http:
            return http.get(f"{API}/{path}")

    def search(self, term: str) -> list[PasteHit]:
        r = self._get(f"search/{term}")
        if r.status_code != 200:
            raise SourceRefused(r.status_code)
        body = r.json()
        data = body.get("data", []) if isinstance(body, dict) else []
        return [PasteHit(paste_id=str(d["id"]), url=f"https://pastebin.com/{d['id']}", body=d.get("text") or "",
                         meta={"time": d.get("time"), "tags": d.get("tags")})
                for d in data[:MAX_RESULTS_PER_TERM] if d.get("id")]

    def fetch(self, hit: PasteHit) -> str:
        r = self._get(f"dump/{hit.paste_id}")
        if r.status_code != 200:
            return hit.body
        try:
            return r.json().get("data", "") or hit.body
        except ValueError:
            return r.text


# A replacement source is added here and selected with PASTE_SOURCE=<key>.
SOURCES: dict[str, type] = {PsbdmpSource.key: PsbdmpSource}


def active_source() -> PasteSource | None:
    cls = SOURCES.get((settings.paste_source or "").strip().lower())
    return cls() if cls else None


def configured_reason() -> tuple[bool, str]:
    """The connector-level part of configured(): enabled and a known source."""
    if not settings.pastes_enabled:
        return False, DISABLED_REASON
    src = active_source()
    if src is None:
        return False, f"PASTE_SOURCE {settings.paste_source!r} is not one of: {', '.join(sorted(SOURCES))}"
    return True, f"paste source: {src.name}"


def _source_row(db: Session, ps: PasteSource) -> Source:
    src = db.execute(select(Source).where(Source.kind == "paste", Source.url == ps.url)).scalar_one_or_none()
    if not src:
        src = Source(name=ps.name, kind="paste", url=ps.url)
        db.add(src)
        db.commit()
    return src


def run(db: Session, source: PasteSource | None = None, pause: float = 1.0) -> dict:
    if source is None:
        ok, reason = configured_reason()
        if not ok:
            return {"ok": True, "skipped": reason}
        source = active_source()
    src = _source_row(db, source)
    terms = db.execute(
        select(WatchTerm.term).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True),
               WatchTerm.kind.in_(("domain", "email_domain", "brand", "keyword")))
    ).scalars().all()
    searched = sorted(set(t.strip() for t in terms if len(t.strip()) >= 4))
    if not searched:
        return {"ok": True, "skipped": "no watch terms to search"}
    refused: list[int] = []
    try:
        for term in searched:
            try:
                hits = source.search(term)
            except SourceRefused as e:
                refused.append(e.status)
                continue
            for h in hits:
                body = source.fetch(h) or h.body
                ingest(
                    db,
                    kind="paste",
                    title=f"Paste {h.paste_id} mentioning {term}",
                    body=(body or "")[:100_000],
                    url=h.url,
                    external_id=f"{source.key}:{h.paste_id}",
                    group_name="pastebin",
                    source=src,
                    meta=h.meta,
                    hash_parts=("paste", h.paste_id),
                )
                time.sleep(pause)
            time.sleep(pause * 2)
        if refused and len(refused) == len(searched):
            err = f"{source.name} returned HTTP {refused[-1]} for all {len(searched)} searches"
            mark_source(db, src, False, err)
            return {"ok": False, "error": err, "terms": len(searched)}
        mark_source(db, src, True)
        return {"ok": True, "terms": len(searched), "refused": len(refused)}
    except Exception as e:  # noqa: BLE001
        log.exception("paste run failed")
        mark_source(db, src, False, str(e))
        return {"ok": False, "error": str(e)}
