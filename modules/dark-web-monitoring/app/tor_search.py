"""Live Tor search (recovery plan Phase 3).

Engine adapters query onion search engines through fetch() over Tor and reduce
each result page to text: title, URL, snippet and the engine that returned it.
Nothing from a result page is executed or rendered as HTML in the console, and
only http(s) URLs survive parsing. A search runs in the worker from the
search_requests table (db.SearchRequest), so the web container never waits on
Tor. Saved searches (db.SavedSearch) re-run on an interval through the same
path and ingest new results as kind "search" items through pipeline.ingest.

Engines and what was verified (Oct 17 to 18, 2026). The sandbox this was built
in cannot reach Tor or ahmia.fi, so nothing below was fetched over Tor; each
engine's address, form and markup come from the sources named and must be
confirmed on the host with `python -m app.diagnose` or a live search.

  ahmia      Verified from Ahmia's own source, github.com/ahmia/ahmia-site at
             commit db1a091 (Sep 25, 2026). The onion service is
             juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion
             (named on the homepage template index_tor.html). The search form
             form#searchForm GETs /search/ with q plus one hidden input whose
             name and value both rotate every minute (views.generate_token and
             rotating_field_names, valid for 60 minutes). /search/ without a
             valid token redirects to the homepage, so the adapter fetches the
             homepage first and copies every hidden input of that form. Results
             are ol.searchResults li.result with h4 a linking through
             /search/redirect?search_term=..&redirect_url=<target>, a p snippet
             and cite holding the domain (tor_results.html). No results is
             p#noResults. Queries over 100 characters or 10 words are refused.
  onionland  Address 3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion
             is listed identically by robin (github.com/apurvsinghgautam/robin,
             search.py, Oct 2, 2026), Sicry (May 2026) and OnionSearch (Dec
             2023). Search is GET /search?q=. Markup comes from OnionSearch's
             parser: .result-block .title a with the target double URL-encoded
             in the l parameter, sponsored links under /ads/, and a
             .search-status summary. Not observed live.
  tor66      Address tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion
             is listed identically by robin, Sicry and OnionSearch. Search is
             GET /search?q=&sorttype=rel&page=1. Markup comes from OnionSearch:
             results follow the first <hr> as <b><a href=target>title</a></b>
             and the page states ".Onion sites found : N". Not observed live.

The fixtures under tests/fixtures/tor_search_*.html reproduce that markup.
Addresses, paths and form fields live in TOR_SEARCH_ENGINES so a dead or moved
engine is swapped without a release."""
from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime as dt
import json
import logging
import re
import time
import unicodedata
from typing import Callable
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import fetch as fetch_mod
from . import pipeline, work_requests
from .config import settings
from .db import AuditLog, Client, SavedSearch, SearchRequest, Source, utcnow

log = logging.getLogger(__name__)

RETENTION_DAYS = 90
MAX_QUERY = 100          # Ahmia refuses longer queries; keep one limit for all engines
MAX_TITLE = 300
MAX_SNIPPET = 500
SAVED_INTERVALS_HOURS = (6, 12, 24, 72, 168)

# ---------------------------------------------------------------- engine configuration
DEFAULT_ENGINES: list[dict] = [
    {
        "key": "ahmia", "name": "Ahmia", "parser": "ahmia", "enabled": True,
        "base_url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "search_path": "/search/", "query_param": "q", "params": {},
        # The homepage carries the rotating hidden token the search form needs.
        "token_path": "/", "token_form": "form#searchForm",
    },
    {
        "key": "onionland", "name": "OnionLand", "parser": "onionland", "enabled": True,
        "base_url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion",
        "search_path": "/search", "query_param": "q", "params": {},
        "token_path": "", "token_form": "",
    },
    {
        "key": "tor66", "name": "Tor66", "parser": "tor66", "enabled": True,
        "base_url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion",
        "search_path": "/search", "query_param": "q", "params": {"sorttype": "rel", "page": "1"},
        "token_path": "", "token_form": "",
    },
]
_FIELDS = ("key", "name", "parser", "enabled", "base_url", "search_path", "query_param", "params",
           "token_path", "token_form")


@dataclasses.dataclass(frozen=True)
class Engine:
    key: str
    name: str
    parser: str
    enabled: bool
    base_url: str
    search_path: str
    query_param: str = "q"
    params: dict = dataclasses.field(default_factory=dict)
    token_path: str = ""
    token_form: str = ""


class EngineConfigError(ValueError):
    pass


def load_engines(raw: str | None = None) -> list[Engine]:
    """Engines from TOR_SEARCH_ENGINES merged over the defaults. Blank uses the
    defaults. The value is a JSON list of objects: an object whose key matches a
    default overrides only the fields it names (for example
    [{"key": "tor66", "enabled": false}]); a new key needs every field the
    parser uses. Raises EngineConfigError on invalid JSON or an unknown parser."""
    raw = settings.tor_search_engines if raw is None else raw
    merged = {e["key"]: dict(e) for e in DEFAULT_ENGINES}
    if raw and raw.strip():
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise EngineConfigError(f"TOR_SEARCH_ENGINES is not valid JSON: {e.msg}") from e
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise EngineConfigError("TOR_SEARCH_ENGINES must be a JSON list of engine objects")
        for obj in data:
            if not isinstance(obj, dict) or not obj.get("key"):
                raise EngineConfigError("every TOR_SEARCH_ENGINES entry needs a key")
            base = merged.get(obj["key"], {"key": obj["key"], "name": obj["key"], "enabled": True,
                                           "query_param": "q", "params": {}, "token_path": "", "token_form": ""})
            base.update({k: v for k, v in obj.items() if k in _FIELDS})
            merged[obj["key"]] = base
    out = []
    for d in merged.values():
        if d.get("parser") not in PARSERS:
            raise EngineConfigError(f"engine {d['key']}: unknown parser {d.get('parser')!r}")
        if not d.get("base_url") or not d.get("search_path"):
            raise EngineConfigError(f"engine {d['key']}: base_url and search_path are required")
        out.append(Engine(**{k: d.get(k) for k in _FIELDS if k in d}))
    return out


def enabled_engines() -> list[Engine]:
    try:
        return [e for e in load_engines() if e.enabled]
    except EngineConfigError:
        return []


def configured() -> tuple[bool, str]:
    try:
        engines = load_engines()
    except EngineConfigError as e:
        return False, str(e)
    on = [e.name for e in engines if e.enabled]
    if not on:
        return False, "no search engine enabled in TOR_SEARCH_ENGINES"
    return True, "engines: " + ", ".join(on)


# ---------------------------------------------------------------- results and link safety
@dataclasses.dataclass
class Result:
    title: str
    url: str
    snippet: str
    engine: str


@dataclasses.dataclass
class EngineOutcome:
    engine: str
    results: list[Result]
    error: str = ""
    ms: int = 0

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        return "ok" if self.results else "empty"


_CTRL = re.compile(r"[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]")


def clean_text(value: str, limit: int) -> str:
    """Plain, single-line text: control, zero-width and bidi override characters
    removed, whitespace collapsed, length capped."""
    s = unicodedata.normalize("NFKC", value or "")
    s = _CTRL.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 3].rstrip() + "..."


def safe_url(url: str) -> str:
    """The URL when it is an absolute http(s) URL with a host and no credentials,
    else an empty string. Anything else (javascript:, data:, relative paths,
    user:pass@ hosts) is never shown as a link or stored as a result."""
    u = (url or "").strip()
    if not u or len(u) > 2000 or any(ch.isspace() for ch in u) or _CTRL.search(u):
        return ""
    try:
        parts = urlsplit(u)
    except ValueError:
        return ""
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return ""
    if parts.username or parts.password:
        return ""
    if not re.fullmatch(r"[a-z0-9.-]+", parts.hostname.lower()):
        return ""
    return u.split("#", 1)[0]


def is_onion_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host.endswith(".onion")


def dedupe_key(url: str) -> str:
    """onion host and path: the identity a result is merged and de-duplicated on.
    Scheme, query, fragment and a trailing slash are ignored."""
    p = urlsplit(url)
    path = re.sub(r"/+$", "", p.path or "") or "/"
    return f"{(p.hostname or '').lower()}{path}"


def merge(outcomes: list[EngineOutcome]) -> list[dict]:
    """Results from every engine merged by onion host and path, in first-seen order
    by engine, each carrying the engines that returned it."""
    merged: dict[str, dict] = {}
    for oc in outcomes:
        for r in oc.results:
            url = safe_url(r.url)
            if not url:
                continue
            key = dedupe_key(url)
            row = merged.get(key)
            if row is None:
                row = merged[key] = {"key": key, "url": url, "host": urlsplit(url).hostname or "",
                                     "title": r.title, "snippet": r.snippet, "engines": [],
                                     "onion": is_onion_url(url)}
            if r.engine not in row["engines"]:
                row["engines"].append(r.engine)
            if not row["title"] and r.title:
                row["title"] = r.title
            if len(r.snippet) > len(row["snippet"]):
                row["snippet"] = r.snippet
    return list(merged.values())


# ---------------------------------------------------------------- parsers
class LayoutChanged(Exception):
    """The page did not carry the markup this adapter expects."""


def _soup(html: str):
    """Parsed page with script, style and similar elements removed, so their
    contents never reach a title or snippet."""
    soup = fetch_mod.soup_of(html)
    for tag in soup(["script", "style", "noscript", "template", "iframe", "object", "svg"]):
        tag.decompose()
    return soup


def _result(engine: Engine, title: str, url: str, snippet: str) -> Result | None:
    url = safe_url(url)
    if not url:
        return None
    # Links back to the engine itself are navigation, never results.
    if (urlsplit(url).hostname or "").lower() == (urlsplit(engine.base_url).hostname or "").lower():
        return None
    return Result(title=clean_text(title, MAX_TITLE) or (urlsplit(url).hostname or ""), url=url,
                  snippet=clean_text(snippet, MAX_SNIPPET), engine=engine.key)


def _ahmia_target(href: str) -> str:
    # The template does not URL-encode redirect_url and puts it last, so a target
    # with its own query string keeps it: take everything after the marker.
    if "redirect_url=" not in href:
        return href
    target = href.split("redirect_url=", 1)[1]
    if target.lower().startswith(("http%3a", "https%3a")):
        target = unquote(target)
    return target


def parse_ahmia(engine: Engine, html: str, limit: int) -> list[Result]:
    soup = _soup(html)
    items = soup.select("ol.searchResults li.result")
    if not items:
        if soup.select_one("#noResults"):
            return []
        raise LayoutChanged("no ol.searchResults and no #noResults on the Ahmia results page")
    out = []
    for li in items:
        a = li.select_one("h4 a")
        if a is None or not a.get("href"):
            continue
        p = li.find("p")
        r = _result(engine, a.get_text(" ", strip=True), _ahmia_target(a["href"]), p.get_text(" ", strip=True) if p else "")
        if r:
            out.append(r)
        if len(out) >= limit:
            break
    return out


def parse_onionland(engine: Engine, html: str, limit: int) -> list[Result]:
    soup = _soup(html)
    blocks = soup.select(".result-block")
    if not blocks:
        if soup.select_one(".search-status"):
            return []
        raise LayoutChanged("no .result-block and no .search-status on the OnionLand results page")
    out = []
    for b in blocks:
        a = b.select_one(".title a")
        if a is None or not a.get("href") or a["href"].startswith("/ads/"):
            continue
        href = a["href"]
        target = ""
        qs = parse_qs(urlsplit(href).query)
        if qs.get("l"):
            target = unquote(qs["l"][0])  # parse_qs decoded once; the value is double encoded
        elif href.startswith(("http://", "https://")):
            target = href
        desc = b.select_one(".desc")
        r = _result(engine, a.get_text(" ", strip=True), target, desc.get_text(" ", strip=True) if desc else "")
        if r:
            out.append(r)
        if len(out) >= limit:
            break
    return out


_TOR66_COUNT = re.compile(r"\.Onion\s+sites\s+found\s*:\s*([0-9]+)", re.I)


def parse_tor66(engine: Engine, html: str, limit: int) -> list[Result]:
    soup = _soup(html)
    hr = soup.find("hr")
    found = _TOR66_COUNT.search(soup.get_text(" "))
    if hr is None or found is None:
        raise LayoutChanged("no '.Onion sites found' count or no <hr> on the Tor66 results page")
    out = []
    for b in hr.find_all_next("b"):
        a = b.find("a")
        if a is None or not a.get("href"):
            continue
        snippet_parts = []
        for sib in b.next_siblings:
            name = getattr(sib, "name", None)
            if name in ("b", "hr"):
                break
            snippet_parts.append(sib.get_text(" ", strip=True) if name else str(sib))
        r = _result(engine, a.get_text(" ", strip=True), a["href"], " ".join(snippet_parts))
        if r:
            out.append(r)
        if len(out) >= limit:
            break
    return out


PARSERS: dict[str, Callable[[Engine, str, int], list[Result]]] = {
    "ahmia": parse_ahmia, "onionland": parse_onionland, "tor66": parse_tor66,
}


# ---------------------------------------------------------------- adapters
def _get(url: str) -> fetch_mod.FetchResult:
    """Every engine request leaves through Tor, onion or clearnet alike."""
    return fetch_mod.fetch(url, force_tor=True, timeout=settings.tor_search_timeout)


def _hidden_inputs(engine: Engine) -> dict:
    """GET the engine's homepage and copy every hidden input of its search form.
    Ahmia rotates both the field name and the value every minute."""
    res = _get(engine.base_url.rstrip("/") + engine.token_path)
    if not res.ok:
        raise RuntimeError(f"homepage fetch failed: {res.error or res.status}")
    soup = _soup(res.text)
    form = soup.select_one(engine.token_form) if engine.token_form else None
    if form is None:
        raise LayoutChanged(f"search form {engine.token_form} not found on the homepage")
    tokens = {i["name"]: i.get("value", "") for i in form.select("input[type=hidden]") if i.get("name")}
    if not tokens:
        raise LayoutChanged(f"no hidden token in {engine.token_form} on the homepage")
    return tokens


def search_url(engine: Engine, query: str, tokens: dict | None = None) -> str:
    params = {engine.query_param: query, **(engine.params or {}), **(tokens or {})}
    return str(httpx.URL(engine.base_url.rstrip("/") + engine.search_path, params=params))


def run_engine(engine: Engine, query: str, limit: int | None = None) -> EngineOutcome:
    """Run one engine. Never raises: a network failure, an HTTP error or a layout
    the parser does not recognise returns an empty list with the error."""
    limit = limit or settings.tor_search_limit
    start = time.monotonic()
    try:
        tokens = _hidden_inputs(engine) if engine.token_path else {}
        res = _get(search_url(engine, query, tokens))
        if not res.ok:
            raise RuntimeError(f"search fetch failed: {res.error or 'HTTP ' + str(res.status)}")
        if engine.token_path and urlsplit(res.url).path in ("", "/") and engine.search_path not in ("", "/"):
            raise RuntimeError("the engine redirected to its homepage; the search token was refused")
        results = PARSERS[engine.parser](engine, res.text or "", limit)
        return EngineOutcome(engine.key, results, "", int((time.monotonic() - start) * 1000))
    except LayoutChanged as e:
        err = f"layout changed: {e}"
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}" if not isinstance(e, RuntimeError) else str(e)
    log.warning("tor search %s failed: %s", engine.key, err)
    return EngineOutcome(engine.key, [], err[:500], int((time.monotonic() - start) * 1000))


class Adapter:
    """The engine adapter interface: search(query, limit) -> list[Result]. The
    outcome of the last call (error and timing) stays on last_outcome."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.last_outcome: EngineOutcome | None = None

    def search(self, query: str, limit: int | None = None) -> list[Result]:
        self.last_outcome = run_engine(self.engine, query, limit)
        return self.last_outcome.results


def adapters() -> list[Adapter]:
    return [Adapter(e) for e in enabled_engines()]


def run_search(query: str, engine_keys: list[str] | None = None, limit: int | None = None) -> dict:
    """Query the chosen enabled engines in parallel and merge the results."""
    engines = [e for e in enabled_engines() if not engine_keys or e.key in engine_keys]
    outcomes: list[EngineOutcome] = []
    if engines:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines)) as pool:
            outcomes = list(pool.map(lambda e: run_engine(e, query, limit), engines))
    return {
        "results": merge(outcomes),
        "engines": {oc.engine: {"status": oc.status, "count": len(oc.results), "error": oc.error, "ms": oc.ms}
                    for oc in outcomes},
    }


def normalise_query(q: str) -> str:
    return clean_text(q, MAX_QUERY + 3)[:MAX_QUERY]


# ---------------------------------------------------------------- requests (web side)
def enqueue(db: Session, query: str, engines: list[str], requested_by: str,
            saved: SavedSearch | None = None) -> SearchRequest:
    valid = {e.key for e in enabled_engines()}
    chosen = [k for k in engines if k in valid] or sorted(valid)
    return work_requests.enqueue(
        db, SearchRequest, requested_by,
        {"query": query, "engines": chosen, "saved_search_id": saved.id if saved else None},
        query=query, engines=chosen, saved_search_id=saved.id if saved else None,
        client_id=saved.client_id if saved else None,
    )


def recent_for(db: Session, user: str, limit: int = 15) -> list[SearchRequest]:
    return list(db.execute(select(SearchRequest).where(SearchRequest.requested_by == user,
                                                       SearchRequest.saved_search_id.is_(None))
                           .order_by(SearchRequest.requested_at.desc()).limit(limit)).scalars())


# ---------------------------------------------------------------- worker side
def _summary(result: dict) -> tuple[bool, str]:
    eng = result.get("engines") or {}
    errors = [f"{k}: {v['error']}" for k, v in eng.items() if v.get("error")]
    ok = bool(eng) and any(not v.get("error") for v in eng.values())
    if not eng:
        errors = ["no enabled engine was selected"]
    return ok, "; ".join(errors)[:2000]


def execute(db: Session, req: SearchRequest) -> dict:
    """Run a claimed request. A saved search also ingests its results."""
    result = run_search(req.query, list(req.engines or []))
    ok, err = _summary(result)
    out = {"ok": ok, "error": err, **result, "total": len(result["results"])}
    if req.saved_search_id:
        out["ingest"] = ingest_saved(db, req, result["results"])
    return out


def search_source(db: Session) -> Source:
    """The single Source row saved-search items hang off, so the Connectors page
    counts them like any other connector's items."""
    s = db.execute(select(Source).where(Source.kind == "search", Source.url == "tor-search://saved")).scalar_one_or_none()
    if s is None:
        s = Source(name="Live Tor search (saved searches)", kind="search", url="tor-search://saved",
                   meta={"seeded_from": "tor_search"})
        db.add(s)
        db.commit()
    return s


def ingest_saved(db: Session, req: SearchRequest, results: list[dict]) -> dict:
    """Ingest a saved search's results as kind "search" items. The hash is the
    onion host and path, so a result seen before (by any saved search) is not
    ingested again and never alerts twice."""
    saved = db.get(SavedSearch, req.saved_search_id)
    src = search_source(db)
    new = hits = 0
    for r in results:
        item, h = pipeline.ingest(
            db, "search", title=r["title"] or r["host"],
            body="\n".join(x for x in (r["title"], r["snippet"], r["url"]) if x),
            url=r["url"], external_id=r["key"], source=src, hash_parts=("search", r["key"]),
            meta={"engines": r["engines"], "query": req.query, "saved_search_id": req.saved_search_id,
                  "client_id": req.client_id, "search_request_id": req.id},
        )
        if item is not None:
            new += 1
            hits += len(h)
    if saved is not None:
        saved.last_new_items = new
        db.commit()
    pipeline.mark_source(db, src, True)
    return {"items_new": new, "hits_new": hits}


def finish_saved(db: Session, req: SearchRequest, ok: bool, error: str) -> None:
    saved = db.get(SavedSearch, req.saved_search_id) if req.saved_search_id else None
    if saved is None:
        return
    saved.last_run_at = utcnow()
    saved.last_request_id = req.id
    saved.last_error = (error or "")[:2000] if not ok else ""
    db.commit()


def drain(db: Session, handler: Callable[[SearchRequest], dict], saved: bool, limit: int = 3) -> int:
    """Claim and run live (saved=False) or saved (saved=True) requests."""
    accept = (lambda r: r.saved_search_id is not None) if saved else (lambda r: r.saved_search_id is None)
    return work_requests.drain(db, SearchRequest, handler, limit=limit, accept=accept)


def queue_due(db: Session, now: dt.datetime | None = None) -> int:
    """Queue every enabled saved search whose next run is due, once. A saved
    search with a request still pending or running is skipped."""
    now = now or utcnow()
    due = db.execute(select(SavedSearch).join(Client, SavedSearch.client_id == Client.id).where(
        SavedSearch.enabled.is_(True), Client.active.is_(True),
        (SavedSearch.next_run_at.is_(None)) | (SavedSearch.next_run_at <= now))).scalars().all()
    n = 0
    for s in due:
        busy = db.execute(select(SearchRequest.id).where(
            SearchRequest.saved_search_id == s.id,
            SearchRequest.status.in_((work_requests.PENDING, work_requests.RUNNING))).limit(1)).first()
        if busy:
            continue
        enqueue(db, s.query, list(s.engines or []), f"saved search by {s.created_by}", saved=s)
        db.add(AuditLog(actor=f"saved-search:{s.id[:8]}", action="search.saved_run",
                        detail=f"client={s.client_id} query={s.query!r} by={s.created_by}"[:4000]))
        s.next_run_at = now + dt.timedelta(hours=max(1, int(s.interval_hours or 24)))
        db.commit()
        n += 1
    return n


def run_saved(db: Session) -> dict:
    """The tor_search connector job: queue due saved searches and run them now
    through the search_requests table. Live searches are drained separately every
    TOR_SEARCH_POLL_SECONDS."""
    queued = queue_due(db)
    totals = {"searches": 0, "engine_errors": []}

    def handle(req: SearchRequest) -> dict:
        out = execute(db, req)
        finish_saved(db, req, out["ok"], out["error"])
        totals["searches"] += 1
        if out["error"]:
            totals["engine_errors"].append(out["error"])
        return out

    drain(db, handle, saved=True, limit=20)
    summary = {"due": queued, "searches": totals["searches"]}
    if totals["engine_errors"]:
        summary["error"] = " | ".join(totals["engine_errors"])[:2000]
    return summary


def engine_health(db: Session) -> dict:
    """Connector page detail: the newest finished search and its per-engine state."""
    last = db.execute(select(SearchRequest).where(SearchRequest.status.in_((work_requests.DONE, work_requests.FAILED)))
                      .order_by(SearchRequest.finished_at.desc()).limit(1)).scalar_one_or_none()
    since = utcnow() - dt.timedelta(days=1)
    n24 = len(db.execute(select(SearchRequest.id).where(SearchRequest.requested_at >= since)).all())
    saved = len(db.execute(select(SavedSearch.id).where(SavedSearch.enabled.is_(True))).all())
    return {"search_engines": (last.result or {}).get("engines", {}) if last else {},
            "searches_24h": n24, "saved_searches": saved}


def client_saved(db: Session, client_id: str) -> list[SavedSearch]:
    return list(db.execute(select(SavedSearch).where(SavedSearch.client_id == client_id)
                           .order_by(SavedSearch.created_at)).scalars())
