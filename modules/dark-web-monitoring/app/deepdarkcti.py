"""deepdarkCTI catalog: curated, status-checked lists of dark web sources.

github.com/fastfire/deepdarkCTI is a community list, updated several times a
week, of ransomware leak sites, forums, markets, onion search engines and
Telegram channels, each row marked ONLINE, OFFLINE, VALID, EXPIRED and so on.
This module reads the raw markdown at run time (it never vendors the files),
keeps only the rows marked online, and uses them two ways:

  ransomware_gang.md   onion leak sites become onion Sources with
                       seeded_from="deepdarkcti". A source starts enabled when
                       its group has posted in a victim feed within
                       ONION_INACTIVE_DAYS, otherwise disabled with code
                       "inactive"; a later refresh enables it once the group is
                       active. Negotiation chats, login and support portals are
                       skipped. A source already known by its onion host is left
                       as it is, so a person's choice or a provider's
                       availability always wins.
  telegram_*.md        public channels (t.me/<name>, never private invite
                       links) are kept in worker state as the catalog the
                       telegram_web connector reads when TELEGRAM_WEB_USE_CATALOG
                       is true.

The lists are data (names, addresses, statuses) and are credited to deepdarkCTI
on every source and in the module README."""
from __future__ import annotations

import datetime as dt
import logging
import re
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import health
from .config import settings
from .db import Source, utcnow
from .fetch import FetchResult, fetch

log = logging.getLogger(__name__)

ATTRIBUTION = "deepdarkCTI (github.com/fastfire/deepdarkCTI)"
RANSOMWARE_FILE = "ransomware_gang.md"
TELEGRAM_FILES = ("telegram_threat_actors.md", "telegram_infostealer.md")
STATE_TELEGRAM = "deepdarkcti:telegram"
STATE_SUMMARY = "deepdarkcti:summary"
ONLINE = {"ONLINE", "VALID"}
# Checked against the parenthetical qualifier ("Akira (Victims request ID page)").
SKIP_QUALIFIER = ("chat", "negotiat", "request", "login", "support", "admin", "panel", "tox", "contact",
                  "jabber", "forum", "market", "rss", "clearnet", "payment", "decrypt", "portal", "file")
# Checked against the whole name: rows that are directories, not one group's site.
SKIP_NAME = ("group sites", "(list)", "telegram", "twitter")
TG_PUBLIC = re.compile(r"^https?://t\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,31})/?$")
ONION_HOST = re.compile(r"^[a-z2-7]{56}\.onion$")
LINK = re.compile(r"\[(?P<name>[^\]]*)\]\((?P<url>[^)\s]+)\)")


def file_url(name: str) -> str:
    return f"{settings.deepdarkcti_base.rstrip('/')}/{name}"


def rows(markdown: str) -> list[list[str]]:
    """Table rows as lists of cell strings, header and separator lines dropped."""
    out = []
    for line in markdown.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or set(cells[0]) <= {"-", " ", ":"}:
            continue
        if cells[0].lower() in ("name", "telegram"):
            continue
        out.append(cells)
    return out


def status_of(cells: list[str]) -> str:
    return (cells[1] if len(cells) > 1 else "").strip().strip('"').upper()


def name_and_url(cell: str) -> tuple[str, str]:
    m = LINK.search(cell)
    if m:
        return m.group("name").strip(), m.group("url").strip()
    return "", cell.strip()


def onion_host(url: str) -> str:
    m = re.match(r"^https?://([^/:?#]+)", url.strip().lower())
    host = m.group(1) if m else ""
    return host if ONION_HOST.match(host) else ""


def group_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def parse_ransomware(markdown: str) -> list[dict]:
    """Online onion leak sites: [{"group", "name", "host", "url"}]."""
    out, seen = [], set()
    for cells in rows(markdown):
        if status_of(cells) not in ONLINE:
            continue
        name, url = name_and_url(cells[0])
        host = onion_host(url)
        if not host or host in seen or not name:
            continue
        base, _, qual = name.partition("(")
        if any(w in name.lower() for w in SKIP_NAME) or any(w in qual.lower() for w in SKIP_QUALIFIER):
            continue
        group = base.strip()
        if not group:
            continue
        seen.add(host)
        out.append({"group": group, "name": name, "host": host, "url": f"http://{host}/",
                    "qualifier": qual.rstrip(")").strip()})
    return out


def parse_telegram(markdown: str, list_name: str) -> list[dict]:
    """Online public channels: [{"channel", "name", "type", "list"}]."""
    out = []
    for cells in rows(markdown):
        if status_of(cells) not in ONLINE:
            continue
        _, url = name_and_url(cells[0])
        m = TG_PUBLIC.match(url.strip())
        if not m or m.group(1).lower() in ("joinchat", "addlist", "s"):
            continue
        out.append({"channel": m.group(1), "name": (cells[2] if len(cells) > 2 else "")[:120],
                    "type": (cells[3] if len(cells) > 3 else "")[:80], "list": list_name})
    return out


def telegram_catalog(db: Session) -> list[dict]:
    st = health.get_state(db, STATE_TELEGRAM) or {}
    return [c for c in st.get("channels") or [] if isinstance(c, dict) and c.get("channel")]


def _seed_onions(db: Session, sites: list[dict], now: dt.datetime) -> dict:
    from . import onion_sources

    window = dt.timedelta(days=settings.onion_inactive_days)
    active = {group_key(k): t for k, t in onion_sources.group_activity(db).items()}
    known = {onion_sources.fqdn_of(s.url): s for s in db.execute(select(Source).where(Source.kind == "onion")).scalars()}
    added = enabled = 0
    for site in sites:
        seen = active.get(group_key(site["group"]))
        is_active = bool(seen and now - seen <= window)
        src = known.get(site["host"])
        if src is not None:
            meta = src.meta or {}
            reason = onion_sources.disabled_reason(src) or {}
            if (meta.get("seeded_from") == "deepdarkcti" and not src.enabled
                    and reason.get("code") == "inactive" and is_active):
                meta = dict(meta)
                meta.pop("disabled", None)
                src.meta = {**meta, "last_seen_in_feed": seen.isoformat()}
                src.enabled = True
                src.fail_count = 0
                enabled += 1
            continue
        src = Source(name=f"{site['group']} leak site", kind="onion", url=site["url"], group_name=site["group"],
                     enabled=True, meta={"seeded_from": "deepdarkcti", "seeded_at": now.isoformat(),
                                         "catalog_name": site["name"], "attribution": ATTRIBUTION})
        if seen:
            src.meta = {**src.meta, "last_seen_in_feed": seen.isoformat()}
        if not is_active:
            onion_sources.disable(src, "inactive", "deepdarkCTI lists it online, but this group has no victim "
                                  f"feed activity in {settings.onion_inactive_days} days", now)
        db.add(src)
        known[site["host"]] = src
        added += 1
    db.commit()
    return {"onion_added": added, "onion_enabled": enabled}


def run(db: Session, get: Callable[[str], FetchResult] | None = None, now: dt.datetime | None = None) -> dict:
    if not settings.deepdarkcti_enabled:
        return {"ok": False, "error": "turned off (DEEPDARKCTI_ENABLED=false)"}
    now = now or utcnow()
    get = get or (lambda url: fetch(url))
    errors: list[str] = []
    out: dict = {}

    def text_of(name: str) -> str | None:
        res = get(file_url(name))
        if not res.ok or not res.text:
            errors.append(f"{name}: {res.error or 'HTTP ' + str(res.status)}")
            return None
        return res.text

    md = text_of(RANSOMWARE_FILE)
    if md is not None:
        sites = parse_ransomware(md)
        out["onion_listed"] = len(sites)
        out.update(_seed_onions(db, sites, now))
    channels: list[dict] = []
    fetched_tg = 0
    for name in TELEGRAM_FILES:
        md = text_of(name)
        if md is None:
            continue
        fetched_tg += 1
        channels += parse_telegram(md, name.removesuffix(".md"))
    if fetched_tg:
        uniq: dict[str, dict] = {}
        for c in channels:
            uniq.setdefault(c["channel"].lower(), c)
        health.set_state(db, STATE_TELEGRAM, {"fetched_at": now.isoformat(), "channels": list(uniq.values())})
        out["telegram_channels"] = len(uniq)
    out["ok"] = len(errors) < 1 + len(TELEGRAM_FILES)
    if errors:
        out["error"] = "; ".join(errors)[:2000]
    health.set_state(db, STATE_SUMMARY, {"at": now.isoformat(), **{k: v for k, v in out.items() if k != "error"}})
    log.info("deepdarkcti: %s", out)
    return out
