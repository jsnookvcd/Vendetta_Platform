"""Infostealer exposure per client domain, from Hudson Rock's free OSINT API.

Hudson Rock (Cavalier) indexes computers infected by infostealers and publishes
a free, keyless lookup that tells you how many infected machines hold
credentials for a domain, split into the domain's own employees, its users
(customers logging in to its sites) and third parties. The same endpoint backs
theHarvester's hudsonrock source, which is where the request and response shape
below were read from (theHarvester/discovery/hudsonrocksearch.py, Oct 2026):

  GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=<d>
  {"total", "employees", "users", "third_parties",
   "data": {"employees_urls": [{"url", "occurrence"}], "users_urls": [...],
            "third_parties_urls": [...]}, ...}
  Hosts Hudson Rock chooses to hide arrive as https://•••; they are dropped.

What this connector does: for every domain on an active client's enabled
domain or email_domain watch terms, at most once per INFOSTEALERS_RECHECK_HOURS,
it asks for the counts. A non-zero result is stored as a stealer item whose body
names the domain, so the matcher raises a credential hit for that client at high
severity. A new item (and so a new alert) appears only when the counts change.
No credential, cookie or password ever reaches this module: the free endpoint
returns counts and login URLs only.

Fair use: one request per domain per run, a pause between requests, a per-run
cap, and a 429 stops the run with the remaining domains left for the next one.
Hudson Rock's terms for the free tools were not readable from the build sandbox;
check them before relying on this for a client deliverable."""
from __future__ import annotations

import datetime as dt
import logging
import time
from typing import Callable
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import health
from ..config import settings
from ..db import Client, Source, WatchTerm, utcnow
from ..fetch import fetch_json
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
SOURCE_NAME = "Hudson Rock infostealer exposure"
STATE_PREFIX = "infostealers:"
PAUSE_SECONDS = 1.5
ATTRIBUTION = "Hudson Rock Cavalier free OSINT tools"
URL_SAMPLES = 15


def domain_url(domain: str) -> str:
    return f"{BASE}/search-by-domain?domain={quote(domain, safe='')}"


def client_domains(db: Session) -> list[str]:
    rows = db.execute(
        select(WatchTerm.term).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True), WatchTerm.kind.in_(("domain", "email_domain")))
    ).scalars().all()
    out: list[str] = []
    for t in rows:
        d = (t or "").strip().lower().lstrip("@").lstrip("*.").rstrip(".")
        if d and "." in d and " " not in d and d not in out:
            out.append(d)
    return sorted(out)


def _count(v) -> int:
    try:
        return max(0, int(v or 0))
    except (TypeError, ValueError):
        return 0


def _urls(data: dict, key: str) -> list[dict]:
    rows = data.get(key) if isinstance(data, dict) else None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        u = str(r.get("url") or "").strip()
        if not u or "•" in u or not u.startswith(("http://", "https://")):
            continue
        out.append({"url": u[:300], "occurrence": _count(r.get("occurrence"))})
    out.sort(key=lambda r: -r["occurrence"])
    return out[:URL_SAMPLES]


def parse(resp: dict) -> dict:
    if not isinstance(resp, dict):
        raise ValueError("response is not an object")
    if resp.get("error"):
        raise ValueError(f"provider error: {str(resp.get('error'))[:200]}")
    if "total" not in resp and "employees" not in resp:
        raise ValueError("response carries neither 'total' nor 'employees'; the schema changed")
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    return {
        "total": _count(resp.get("total")),
        "employees": _count(resp.get("employees")),
        "users": _count(resp.get("users")),
        "third_parties": _count(resp.get("third_parties")),
        "employee_urls": _urls(data, "employees_urls"),
        "user_urls": _urls(data, "users_urls"),
    }


def _host(url: str) -> str:
    try:
        return httpx.URL(url).host or url
    except Exception:  # noqa: BLE001
        return url


def _body(domain: str, r: dict) -> str:
    # Written without "label: value" pairs: the stealer kind is redacted at
    # ingest and a colon pair would mask the domain the matcher needs.
    lines = [
        f"Hudson Rock reports {r['total']} computers infected by infostealers that hold credentials for {domain}.",
        f"{r['employees']} belong to {domain} employees, {r['users']} to users of its sites and "
        f"{r['third_parties']} to third parties.",
        f"Affected employee accounts are logins on the {domain} email domain (anyone@{domain}).",
    ]
    if r["employee_urls"]:
        lines.append("")
        lines.append("Employee login hosts seen in stealer logs, most frequent first (full URLs in the item record)")
        lines += [f"{_host(u['url'])} ({u['occurrence']})" for u in r["employee_urls"]]
    if r["user_urls"]:
        lines.append("")
        lines.append("User login hosts seen in stealer logs, most frequent first")
        lines += [f"{_host(u['url'])} ({u['occurrence']})" for u in r["user_urls"]]
    return "\n".join(lines)


def _source(db: Session) -> Source:
    src = db.execute(select(Source).where(Source.kind == "stealer", Source.url == BASE)).scalar_one_or_none()
    if not src:
        src = Source(name=SOURCE_NAME, kind="stealer", url=BASE, meta={"attribution": ATTRIBUTION})
        db.add(src)
        db.commit()
    return src


def due(db: Session, domain: str, now: dt.datetime) -> bool:
    st = health.get_state(db, STATE_PREFIX + domain) or {}
    at = st.get("checked_at")
    if not at:
        return True
    try:
        last = dt.datetime.fromisoformat(at)
    except ValueError:
        return True
    return now - last >= dt.timedelta(hours=settings.infostealers_recheck_hours)


def run(db: Session, get_json: Callable[[str], dict] | None = None, sleep: Callable[[float], None] = time.sleep,
        now: dt.datetime | None = None) -> dict:
    if not settings.infostealers_enabled:
        return {"ok": False, "new": 0, "error": "turned off (INFOSTEALERS_ENABLED=false)"}
    now = now or utcnow()
    get_json = get_json or (lambda url: fetch_json(url, headers={"Accept": "application/json"}))
    src = _source(db)
    domains = [d for d in client_domains(db) if due(db, d, now)][: settings.infostealers_max_domains_per_run]
    checked = exposed = new = 0
    errors: list[str] = []
    for i, domain in enumerate(domains):
        if i:
            sleep(PAUSE_SECONDS)
        try:
            r = parse(get_json(domain_url(domain)))
        except httpx.HTTPError as e:
            msg = str(e)
            errors.append(f"{domain}: {msg[:200]}")
            if "HTTP 429" in msg:
                break
            continue
        except ValueError as e:
            errors.append(f"{domain}: {e}")
            continue
        checked += 1
        health.set_state(db, STATE_PREFIX + domain, {"checked_at": now.isoformat(),
                                                     **{k: r[k] for k in ("total", "employees", "users",
                                                                          "third_parties")}})
        if r["total"] <= 0 and r["employees"] <= 0:
            continue
        exposed += 1
        item, _ = ingest(
            db,
            kind="stealer",
            title=f"Infostealer exposure for {domain}: {r['employees']} employee and {r['users']} user machines",
            body=_body(domain, r),
            url=f"https://www.hudsonrock.com/search/domain/{quote(domain, safe='')}",
            external_id=f"hudsonrock:{domain}:{r['total']}:{r['employees']}:{r['users']}",
            published_at=now,
            source=src,
            meta={"domain": domain, "counts": {k: r[k] for k in ("total", "employees", "users", "third_parties")},
                  "employee_urls": r["employee_urls"], "user_urls": r["user_urls"], "attribution": ATTRIBUTION},
            hash_parts=("stealer", "hudsonrock", domain, str(r["total"]), str(r["employees"]), str(r["users"])),
            preserve_on_hit=False,
        )
        new += 1 if item else 0
    ok = not errors or checked > 0
    mark_source(db, src, ok, "; ".join(errors)[:2000])
    out = {"ok": ok, "domains_due": len(domains), "checked": checked, "exposed": exposed, "new": new}
    if errors:
        out["error"] = "; ".join(errors)[:2000]
    log.info("infostealers: %s", out)
    return out
