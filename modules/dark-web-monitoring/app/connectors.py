"""Connector registry. Every collector the worker schedules is declared here once,
with what it needs to run and how to tell whether it is working. The worker
builds its schedule from CONNECTORS; the Connectors page, the dashboard banner,
readiness and `python -m app.diagnose` all read status() from here, so a new
connector appears everywhere by adding one entry.

Each connector has:
  key              stable id, also the scheduler job id and CollectorRun.job_id
  name, kind       display name and category (feed, onion, forum, paste, ct,
                   hibp, telegram, search, capture)
  interval_setting the Settings attribute holding the interval in minutes
  job              run(db) -> summary dict; raising marks the run failed
  check            check(db) -> (configured, reason). The reason explains why a
                   connector is off, or carries a caveat when it is on
  source_kind / source_url_like  which Source rows hold this connector's items
  live_feed        True when a healthy run should yield recently published items;
                   such a connector is flagged stale when its newest item is old
  run_at_start     schedule the first run seconds after the worker starts
  probes           upstream endpoints the diagnose CLI checks live

Later phases add entries here (capture queue, saved Tor searches) and may hang a
`extra` callable on an entry to add columns such as queue depth."""
from __future__ import annotations

import dataclasses
import datetime as dt
import importlib.util
import os
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import health, profiles
from .collectors import ct_logs, forum_crawl, hibp, leak_feeds, onion_crawl, pastes, telegram
from .config import settings
from .db import Client, CollectorRun, Item, RunRequest, SessionLocal, Source, WatchTerm, utcnow

STALE_DAYS = 7


@dataclasses.dataclass(frozen=True)
class Probe:
    label: str
    url: str
    headers: dict = dataclasses.field(default_factory=dict)  # never printed
    tor: bool = False


@dataclasses.dataclass(frozen=True)
class Connector:
    key: str
    name: str
    kind: str
    interval_setting: str
    job: Callable[[Session], Any]
    check: Callable[[Session], tuple[bool, str]]
    source_kind: str
    source_url_like: str = ""
    live_feed: bool = False
    run_at_start: bool = False
    probes: Callable[[], list[Probe]] = lambda: []
    extra: Callable[[Session], dict] | None = None
    scheduled: bool = True   # False: never on the worker schedule (a one-time backfill)
    archived: bool = False   # upstream is archived; never shown as a live, healthy feed

    @property
    def job_id(self) -> str:
        return self.key

    @property
    def interval_minutes(self) -> int:
        return int(getattr(settings, self.interval_setting))

    def configured(self, db: Session | None = None) -> tuple[bool, str]:
        if db is not None:
            return self.check(db)
        own = SessionLocal()
        try:
            return self.check(own)
        finally:
            own.close()

    def source_filter(self):
        clause = Source.kind == self.source_kind
        if self.source_url_like:
            clause = clause & Source.url.ilike(self.source_url_like)
        return clause


# ---------------------------------------------------------------- configured() checks
def _term_count(db: Session, kinds: tuple[str, ...]) -> int:
    return db.scalar(
        select(func.count(WatchTerm.id)).join(Client)
        .where(WatchTerm.enabled.is_(True), Client.active.is_(True), WatchTerm.kind.in_(kinds))
    ) or 0


def _check_ransomware_live(db: Session) -> tuple[bool, str]:
    if settings.ransomware_live_api_key:
        return True, ""
    return False, "needs a free PRO key from my.ransomware.live (RANSOMWARE_LIVE_API_KEY)"


def _check_ransomwatch(db: Session) -> tuple[bool, str]:
    return True, "archived upstream in mid-2025; one-time historical backfill only"


def _check_onion(db: Session) -> tuple[bool, str]:
    n = db.scalar(select(func.count(Source.id)).where(Source.kind == "onion", Source.enabled.is_(True))) or 0
    if not n:
        return False, "no enabled onion sources; seeding runs at worker start and daily"
    return True, f"{n} enabled onion sources"


def _check_forum(db: Session) -> tuple[bool, str]:
    """On only when a forum-kind profile exists (files starting with _ are examples)
    and an enabled forum Source references it. See the README forum guide."""
    forum_profiles = {k for k, v in profiles.all_profiles().items()
                      if v.get("kind") == "forum" and not k.startswith("_")}
    if not forum_profiles:
        return False, "no forum profiles configured"
    srcs = db.execute(select(Source.profile).where(Source.kind == "forum", Source.enabled.is_(True))).scalars().all()
    usable = [p for p in srcs if p in forum_profiles]
    if not usable:
        return False, ("no forum profiles configured on a source: add an enabled forum Source that uses one of "
                       + ", ".join(sorted(forum_profiles)))
    return True, f"{len(usable)} forum sources"


def _check_hibp(db: Session) -> tuple[bool, str]:
    if not settings.hibp_api_key:
        return False, "needs HIBP_API_KEY"
    if not _term_count(db, ("domain", "email_domain")):
        return False, "no domain or email_domain watch terms"
    return True, ""


def _check_ct(db: Session) -> tuple[bool, str]:
    if not _term_count(db, ("domain",)):
        return False, "no domain watch terms"
    return True, ""


def _check_pastes(db: Session) -> tuple[bool, str]:
    ok, reason = pastes.configured_reason()
    if not ok:
        return False, reason
    if not _term_count(db, ("domain", "email_domain", "brand", "keyword")):
        return False, "no domain, email_domain, brand or keyword watch terms"
    return True, reason


def _check_telegram(db: Session) -> tuple[bool, str]:
    missing = [n for n, v in (("TELEGRAM_API_ID", settings.telegram_api_id),
                              ("TELEGRAM_API_HASH", settings.telegram_api_hash),
                              ("TELEGRAM_CHANNELS", settings.telegram_channels)) if not v]
    if missing:
        return False, "needs " + ", ".join(missing)
    if importlib.util.find_spec("telethon") is None:
        return False, "telethon is not installed"
    if not os.path.exists(telegram.session_path()):
        return False, f"missing Telegram session file at {telegram.session_path()}; run scripts/telegram_login.py"
    return True, ""


# ---------------------------------------------------------------- probes (diagnose only)
def _probe_rl() -> list[Probe]:
    if not settings.ransomware_live_api_key:
        return []  # never call the public v2 tier
    return [Probe("ransomware.live PRO recent victims", f"{leak_feeds._rl_base()}/victims/recent", leak_feeds.rl_headers())]


def _probe_hibp() -> list[Probe]:
    if settings.hibp_api_key:
        return [Probe("HIBP subscription status", f"{hibp.BASE}/subscription/status",
                      {"hibp-api-key": settings.hibp_api_key, "user-agent": "VendettaDarkWebMonitor"})]
    return [Probe("HIBP public breaches list", f"{hibp.BASE}/breaches?domain=example.com")]


CONNECTORS: list[Connector] = [
    Connector("ransomware_live", "ransomware.live victims", "feed", "leak_feed_interval",
              leak_feeds.run_ransomware_live, _check_ransomware_live, "feed", "%ransomware.live%",
              live_feed=True, run_at_start=True, probes=_probe_rl),
    Connector("ransomwatch", "ransomwatch posts (archive)", "feed", "leak_feed_interval",
              leak_feeds.run_ransomwatch_posts, _check_ransomwatch, "feed", "%ransomwatch%",
              probes=lambda: [Probe("ransomwatch posts.json", leak_feeds.RANSOMWATCH_POSTS)],
              scheduled=False, archived=True),
    Connector("onion_crawl", "Onion leak site crawl", "onion", "onion_crawl_interval",
              onion_crawl.run, _check_onion, "onion",
              probes=lambda: [Probe("Tor exit check", "https://check.torproject.org/api/ip", tor=True)]),
    Connector("forum_crawl", "Forum and market crawl", "forum", "forum_crawl_interval",
              forum_crawl.run, _check_forum, "forum"),
    Connector("hibp", "Have I Been Pwned", "hibp", "hibp_interval", hibp.run, _check_hibp, "hibp",
              probes=_probe_hibp),
    Connector("ct_logs", "Certificate transparency (crt.sh)", "ct", "ct_interval", ct_logs.run, _check_ct, "ct",
              probes=lambda: [Probe("crt.sh", "https://crt.sh/?q=example.com&output=json")]),
    Connector("pastes", "Paste index (psbdmp)", "paste", "paste_interval", pastes.run, _check_pastes, "paste",
              probes=lambda: [Probe("psbdmp search", f"{pastes.API}/search/example.com")]),
    Connector("telegram", "Telegram channels", "telegram", "telegram_interval", telegram.run, _check_telegram,
              "telegram"),
]

_BY_KEY = {c.key: c for c in CONNECTORS}


def get(key: str) -> Connector | None:
    return _BY_KEY.get(key)


# ---------------------------------------------------------------- status
def _iso(v: dt.datetime | None) -> str | None:
    return v.isoformat() if v else None


def connector_status(db: Session, c: Connector, now: dt.datetime | None = None) -> dict:
    now = now or utcnow()
    configured, reason = c.configured(db)
    last = db.execute(
        select(CollectorRun).where(CollectorRun.job_id == c.job_id).order_by(CollectorRun.started_at.desc()).limit(1)
    ).scalar_one_or_none()
    last_ok = db.scalar(select(func.max(CollectorRun.finished_at)).where(
        CollectorRun.job_id == c.job_id, CollectorRun.ok.is_(True)))
    base = select(func.count(Item.id)).join(Source, Item.source_id == Source.id).where(c.source_filter())
    items_24h = db.scalar(base.where(Item.collected_at >= now - dt.timedelta(days=1))) or 0
    items_7d = db.scalar(base.where(Item.collected_at >= now - dt.timedelta(days=7))) or 0
    newest = db.scalar(select(func.max(Item.published_at)).join(Source, Item.source_id == Source.id)
                       .where(c.source_filter()))
    stale = bool(c.live_feed and not c.archived and configured and last_ok is not None
                 and (newest is None or newest < now - dt.timedelta(days=STALE_DAYS)))
    last_failed = bool(last is not None and last.ok is False)
    if c.archived:
        state = "archived"
    elif not configured:
        state = "off"
    elif last_failed:
        state = "fail"
    elif stale:
        state = "stale"
    elif last is None:
        state = "never"
    elif last.ok is None:
        state = "running"
    else:
        state = "ok"
    row = {
        "key": c.key, "name": c.name, "kind": c.kind, "interval_minutes": c.interval_minutes,
        "configured": configured, "reason": reason, "live_feed": c.live_feed,
        "last_run_at": last.started_at if last else None,
        "last_run_ok": last.ok if last else None,
        "last_run_trigger": last.trigger if last else None,
        "last_ok": last_ok,
        "items_24h": items_24h, "items_7d": items_7d, "newest_published": newest,
        "error": last.error if last_failed else "",
        "stale": stale, "state": state, "scheduled": c.scheduled, "archived": c.archived,
    }
    if c.extra is not None:
        row.update(c.extra(db))
    return row


def status(db: Session, now: dt.datetime | None = None) -> list[dict]:
    now = now or utcnow()
    pend = {}
    for r in db.execute(select(RunRequest).where(RunRequest.status.in_(("pending", "running")))).scalars():
        pend.setdefault((r.payload or {}).get("connector"), []).append(r.status)
    rows = []
    for c in CONNECTORS:
        row = connector_status(db, c, now)
        row["queued"] = pend.get(c.key, [])
        rows.append(row)
    return rows


def health_summary(db: Session, now: dt.datetime | None = None) -> dict:
    """Worker heartbeat, Tor and connector rows plus the banner the dashboard shows.
    Red: the worker is silent or Tor is not exiting through Tor. Amber: a
    configured connector failed its last run or is stale."""
    now = now or utcnow()
    age = health.heartbeat_age_seconds(db, now)
    tor = health.tor_status(db)
    rows = status(db, now)
    red: list[str] = []
    amber: list[str] = []
    if age is None:
        red.append("The collector worker has never reported a heartbeat.")
    elif age > health.HEARTBEAT_STALE_SECONDS:
        red.append(f"The collector worker last reported {age // 60} minutes ago.")
    if not tor:
        red.append("No Tor check has been recorded.")
    elif not tor.get("is_tor"):
        red.append("Tor is not exiting through Tor" + (f": {tor['error']}" if tor.get("error") else "."))
    failed = [r["name"] for r in rows if r["state"] == "fail"]
    broken = sorted({b["profile"] for r in rows for b in (r.get("broken_profiles") or [])})
    if broken:
        amber.append("Parser profile extracts nothing now: " + ", ".join(broken) + ".")
    stale = [r["name"] for r in rows if r["state"] == "stale"]
    if failed:
        amber.append("Last run failed: " + ", ".join(failed) + ".")
    if stale:
        amber.append(f"No item published in the last {STALE_DAYS} days: " + ", ".join(stale) + ".")
    level = "red" if red else ("amber" if amber else "")
    return {"heartbeat_age_seconds": age, "tor": tor, "connectors": rows,
            "banner": {"level": level, "messages": red + amber}}


# ---------------------------------------------------------------- Phase 2: capture queue and onion extras
# Appended as its own block so later phases can add entries without touching it.
from . import captures as _captures  # noqa: E402
from . import profile_store as _profile_store  # noqa: E402


def _check_captures(db: Session) -> tuple[bool, str]:
    return True, "drains hit captures over Tor"


def _capture_extra(db: Session) -> dict:
    return _captures.stats(db)


def _onion_extra(db: Session) -> dict:
    disabled: dict[str, int] = {}
    for meta in db.execute(select(Source.meta).where(Source.kind == "onion", Source.enabled.is_(False))).scalars():
        code = ((meta or {}).get("disabled") or {}).get("code") or "unspecified"
        disabled[code] = disabled.get(code, 0) + 1
    return {"broken_profiles": _profile_store.broken_profiles(db), "disabled_sources": disabled}


CONNECTORS[:] = [dataclasses.replace(c, extra=_onion_extra) if c.key == "onion_crawl" else c for c in CONNECTORS]
CONNECTORS.append(
    Connector("captures", "Direct capture queue", "capture", "capture_interval", _captures.drain, _check_captures,
              "capture", extra=_capture_extra))
_BY_KEY.clear()
_BY_KEY.update({c.key: c for c in CONNECTORS})
